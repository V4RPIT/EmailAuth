"""RFC 7208 Sender Policy Framework (SPF) evaluator.

Supports mechanisms: `all`, `ip4`, `ip6`, `a`, `mx`, `include`, `exists`,
modifier `redirect=`, qualifiers `+`, `-`, `~`, `?`, and the RFC 7208
10-DNS-lookup limit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import List, Optional

from .dns_store import DNSZoneStore, normalize_domain


_QUALIFIER_TO_RESULT = {
    "+": "pass",
    "-": "fail",
    "~": "softfail",
    "?": "neutral",
}

_MAX_DNS_LOOKUPS = 10


@dataclass
class SPFMechanismTrace:
    """Single step recorded during SPF evaluation."""

    domain: str
    term: str
    matched: bool
    detail: str


@dataclass
class SPFResult:
    """Structured outcome of an SPF check."""

    result: str  # pass, fail, softfail, neutral, none, temperror, permerror
    domain: str
    client_ip: str
    record: Optional[str] = None
    explanation: str = ""
    dns_lookups: int = 0
    matched_mechanism: Optional[str] = None
    traces: List[SPFMechanismTrace] = field(default_factory=list)


def extract_domain_from_address(address: str) -> str:
    """Extract the domain part from an email address like `<user@example.com>`."""
    cleaned = address.strip().strip("<>").strip()
    if "@" in cleaned:
        return normalize_domain(cleaned.rsplit("@", 1)[1])
    return normalize_domain(cleaned)


def _match_ip_network(
    client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address, cidr_str: str
) -> bool:
    network = ipaddress.ip_network(cidr_str, strict=False)
    return client_ip.version == network.version and client_ip in network


def _split_target_and_cidr(spec: str, default_domain: str) -> tuple[str, Optional[int], Optional[int]]:
    """Parse `domain/cidr4//cidr6` syntax used by `a` and `mx` mechanisms."""
    target = default_domain
    cidr4: Optional[int] = None
    cidr6: Optional[int] = None
    if "//" in spec:
        left, c6 = spec.split("//", 1)
        cidr6 = int(c6)
        spec = left
    if "/" in spec:
        left, c4 = spec.split("/", 1)
        if left:
            target = normalize_domain(left)
        if c4:
            cidr4 = int(c4)
    elif spec:
        target = normalize_domain(spec)
    return target, cidr4, cidr6


def evaluate_spf(
    client_ip: str,
    mail_from: str,
    dns_store: DNSZoneStore,
    helo_domain: Optional[str] = None,
) -> SPFResult:
    """Evaluate SPF for `(client_ip, mail_from)` using `dns_store`."""
    try:
        ip_obj = ipaddress.ip_address(client_ip.strip())
    except ValueError as exc:
        return SPFResult(
            result="permerror",
            domain=extract_domain_from_address(mail_from),
            client_ip=client_ip,
            explanation=f"Invalid client IP address: {exc}",
        )

    domain = extract_domain_from_address(mail_from)
    if not domain and helo_domain:
        domain = normalize_domain(helo_domain)
    if not domain:
        return SPFResult(
            result="none",
            domain="",
            client_ip=str(ip_obj),
            explanation="No MAIL FROM or HELO domain available for SPF check.",
        )

    traces: List[SPFMechanismTrace] = []
    lookup_counter = [0]

    def _consume_lookup(eval_domain: str, term: str) -> bool:
        lookup_counter[0] += 1
        if lookup_counter[0] > _MAX_DNS_LOOKUPS:
            traces.append(
                SPFMechanismTrace(
                    domain=eval_domain,
                    term=term,
                    matched=False,
                    detail=f"Exceeded RFC 7208 limit of {_MAX_DNS_LOOKUPS} DNS lookups.",
                )
            )
            return False
        return True

    def _eval_domain(eval_domain: str, depth: int = 0) -> tuple[str, Optional[str], Optional[str], str]:
        if depth > 10:
            return "permerror", None, None, "SPF recursion depth exceeded."

        spf_records = [
            txt
            for txt in dns_store.query(eval_domain, "TXT")
            if txt.lower() == "v=spf1" or txt.lower().startswith("v=spf1 ")
        ]
        if not spf_records:
            return "none", None, None, f"No SPF TXT record found for {eval_domain}."
        if len(spf_records) > 1:
            return "permerror", None, None, f"Multiple SPF TXT records found for {eval_domain} (RFC 7208 violation)."

        record = spf_records[0]
        tokens = record.split()[1:]
        redirect_domain: Optional[str] = None

        for raw_term in tokens:
            if "=" in raw_term and not raw_term.startswith(("+", "-", "~", "?")):
                mod_name, mod_val = raw_term.split("=", 1)
                if mod_name.lower() == "redirect":
                    redirect_domain = normalize_domain(mod_val)
                continue

            qualifier = "+"
            term = raw_term
            if term[0] in _QUALIFIER_TO_RESULT:
                qualifier = term[0]
                term = term[1:]

            mech_name, _, mech_arg = term.partition(":")
            if "/" in mech_name and ":" not in term:
                # Handle `a/24` or `mx/24` without colon
                mech_name, _, slash_part = term.partition("/")
                mech_arg = "/" + slash_part
            mech_lower = mech_name.lower()
            outcome = _QUALIFIER_TO_RESULT[qualifier]

            if mech_lower == "all":
                traces.append(
                    SPFMechanismTrace(
                        domain=eval_domain,
                        term=raw_term,
                        matched=True,
                        detail=f"Catch-all mechanism matched -> {outcome}",
                    )
                )
                return outcome, record, raw_term, f"Matched '{raw_term}' on {eval_domain}."

            if mech_lower == "ip4" or mech_lower == "ip6":
                try:
                    matched = _match_ip_network(ip_obj, mech_arg)
                except ValueError:
                    return "permerror", record, raw_term, f"Invalid CIDR in {raw_term}."
                traces.append(
                    SPFMechanismTrace(
                        domain=eval_domain,
                        term=raw_term,
                        matched=matched,
                        detail=f"IP {ip_obj} {'in' if matched else 'not in'} {mech_arg}",
                    )
                )
                if matched:
                    return outcome, record, raw_term, f"Sender IP {ip_obj} authorized by {raw_term}."
                continue

            if mech_lower == "a":
                if not _consume_lookup(eval_domain, raw_term):
                    return "permerror", record, raw_term, "SPF DNS lookup limit (10) exceeded."
                target, c4, c6 = _split_target_and_cidr(mech_arg, eval_domain)
                ips = dns_store.query(target, "A") + dns_store.query(target, "AAAA")
                matched = False
                for candidate in ips:
                    try:
                        c_ip = ipaddress.ip_address(candidate)
                        prefix = c4 if c_ip.version == 4 else c6
                        cidr = f"{c_ip}/{prefix}" if prefix is not None else str(c_ip)
                        if _match_ip_network(ip_obj, cidr):
                            matched = True
                            break
                    except ValueError:
                        continue
                traces.append(
                    SPFMechanismTrace(
                        domain=eval_domain,
                        term=raw_term,
                        matched=matched,
                        detail=f"Checked A/AAAA records of {target}: {ips}",
                    )
                )
                if matched:
                    return outcome, record, raw_term, f"Sender IP {ip_obj} matched A/AAAA of {target}."
                continue

            if mech_lower == "mx":
                if not _consume_lookup(eval_domain, raw_term):
                    return "permerror", record, raw_term, "SPF DNS lookup limit (10) exceeded."
                target, c4, c6 = _split_target_and_cidr(mech_arg, eval_domain)
                mx_hosts = dns_store.query(target, "MX")
                matched = False
                for mx_entry in mx_hosts:
                    mx_host = mx_entry.split()[-1]
                    mx_ips = dns_store.query(mx_host, "A") + dns_store.query(mx_host, "AAAA")
                    for candidate in mx_ips:
                        try:
                            c_ip = ipaddress.ip_address(candidate)
                            prefix = c4 if c_ip.version == 4 else c6
                            cidr = f"{c_ip}/{prefix}" if prefix is not None else str(c_ip)
                            if _match_ip_network(ip_obj, cidr):
                                matched = True
                                break
                        except ValueError:
                            continue
                    if matched:
                        break
                traces.append(
                    SPFMechanismTrace(
                        domain=eval_domain,
                        term=raw_term,
                        matched=matched,
                        detail=f"Checked MX hosts of {target}: {mx_hosts}",
                    )
                )
                if matched:
                    return outcome, record, raw_term, f"Sender IP {ip_obj} matched MX of {target}."
                continue

            if mech_lower == "include":
                if not mech_arg:
                    return "permerror", record, raw_term, "Empty domain in include mechanism."
                if not _consume_lookup(eval_domain, raw_term):
                    return "permerror", record, raw_term, "SPF DNS lookup limit (10) exceeded."
                inc_domain = normalize_domain(mech_arg)
                inc_res, _, inc_mech, inc_expl = _eval_domain(inc_domain, depth + 1)
                if inc_res in ("none", "permerror"):
                    return "permerror", record, raw_term, f"include:{inc_domain} -> {inc_res}: {inc_expl}"
                matched = inc_res == "pass"
                traces.append(
                    SPFMechanismTrace(
                        domain=eval_domain,
                        term=raw_term,
                        matched=matched,
                        detail=f"include:{inc_domain} evaluated to {inc_res}",
                    )
                )
                if matched:
                    return outcome, record, f"{raw_term} ({inc_mech})", f"Matched via include:{inc_domain}."
                continue

            if mech_lower == "exists":
                if not _consume_lookup(eval_domain, raw_term):
                    return "permerror", record, raw_term, "SPF DNS lookup limit (10) exceeded."
                target = normalize_domain(mech_arg)
                matched = bool(dns_store.query(target, "A"))
                traces.append(
                    SPFMechanismTrace(
                        domain=eval_domain,
                        term=raw_term,
                        matched=matched,
                        detail=f"exists:{target} -> {'found' if matched else 'absent'}",
                    )
                )
                if matched:
                    return outcome, record, raw_term, f"Matched exists:{target}."
                continue

            return "permerror", record, raw_term, f"Unsupported SPF mechanism '{raw_term}'."

        if redirect_domain:
            if not _consume_lookup(eval_domain, f"redirect={redirect_domain}"):
                return "permerror", record, f"redirect={redirect_domain}", "SPF DNS lookup limit (10) exceeded."
            return _eval_domain(redirect_domain, depth + 1)

        return "neutral", record, None, f"No mechanism matched in {eval_domain}; defaulting to neutral."

    res, rec, matched_mech, explanation = _eval_domain(domain)
    return SPFResult(
        result=res,
        domain=domain,
        client_ip=str(ip_obj),
        record=rec,
        explanation=explanation,
        dns_lookups=lookup_counter[0],
        matched_mechanism=matched_mech,
        traces=traces,
    )
