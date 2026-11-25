"""RFC 7489 Domain-based Message Authentication, Reporting, and Conformance (DMARC).

Implements:
- Organizational domain extraction & identifier alignment (`adkim`, `aspf`: relaxed vs strict)
- Policy lookup on `_dmarc.<from_domain>` with fallback to `_dmarc.<org_domain>`
- Effective disposition resolution (`none`, `quarantine`, `reject`) honoring `sp=` and `pct=`
- Monitoring-to-Enforcement lifecycle manager (`p=none` -> `p=quarantine` -> `p=reject`)
- Aggregate (`rua`) XML and structured JSON feedback report generation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parseaddr
import hashlib
from typing import Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from .dkim import DKIMVerificationResult
from .dns_store import DNSZoneStore, normalize_domain
from .spf import SPFResult


# Common multi-level public suffixes for organizational domain extraction
_MULTI_LEVEL_TLDS = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "co.in",
    "co.jp",
}


def get_organizational_domain(domain: str) -> str:
    """Return the organizational domain (eTLD+1) per RFC 7489 Section 3.2."""
    norm = normalize_domain(domain)
    labels = [lbl for lbl in norm.split(".") if lbl]
    if len(labels) <= 2:
        return norm
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LEVEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def domains_align(domain_a: Optional[str], domain_b: Optional[str], mode: str = "r") -> bool:
    """Check RFC 7489 identifier alignment (strict 's' vs relaxed 'r')."""
    if not domain_a or not domain_b:
        return False
    a = normalize_domain(domain_a)
    b = normalize_domain(domain_b)
    if mode.lower() == "s":
        return a == b
    return get_organizational_domain(a) == get_organizational_domain(b)


def parse_dmarc_record(record: str) -> Dict[str, str]:
    """Parse a DMARC TXT record into tag-value pairs."""
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        tags[k.strip().lower()] = v.strip()
    return tags


def extract_from_domain(from_header: str) -> str:
    """Extract the RFC 5322 `From` header domain."""
    _, addr = parseaddr(from_header or "")
    if "@" in addr:
        return normalize_domain(addr.rsplit("@", 1)[1])
    return ""


@dataclass
class DMARCResult:
    """Structured DMARC evaluation outcome."""

    result: str  # pass, fail, none, permerror
    disposition: str  # accept, quarantine, reject
    from_domain: str
    policy: Optional[str] = None  # none, quarantine, reject
    subdomain_policy: Optional[str] = None
    adkim: str = "r"
    aspf: str = "r"
    pct: int = 100
    spf_aligned: bool = False
    dkim_aligned: bool = False
    aligned_dkim_domain: Optional[str] = None
    dmarc_record: Optional[str] = None
    record_domain: Optional[str] = None
    rua: Optional[str] = None
    ruf: Optional[str] = None
    reason: str = ""


def evaluate_dmarc(
    from_header: str,
    spf_result: SPFResult,
    dkim_results: List[DKIMVerificationResult],
    dns_store: DNSZoneStore,
    message_id: str = "",
) -> DMARCResult:
    """Evaluate DMARC authentication, alignment, and policy disposition."""
    from_domain = extract_from_domain(from_header)
    if not from_domain:
        return DMARCResult(
            result="permerror",
            disposition="reject",
            from_domain="",
            reason="Missing or unparseable RFC 5322 From domain.",
        )

    org_domain = get_organizational_domain(from_domain)
    record = dns_store.get_dmarc(from_domain)
    record_domain = from_domain
    is_subdomain = False
    if not record and org_domain != from_domain:
        record = dns_store.get_dmarc(org_domain)
        record_domain = org_domain
        is_subdomain = True

    if not record:
        return DMARCResult(
            result="none",
            disposition="accept",
            from_domain=from_domain,
            reason=f"No DMARC policy published at _dmarc.{from_domain}.",
        )

    tags = parse_dmarc_record(record)
    if tags.get("v") != "DMARC1" or "p" not in tags:
        return DMARCResult(
            result="permerror",
            disposition="accept",
            from_domain=from_domain,
            dmarc_record=record,
            record_domain=record_domain,
            reason="Invalid DMARC record: missing v=DMARC1 or p= tag.",
        )

    policy = tags["p"].lower()
    sp = tags.get("sp", policy).lower()
    adkim = tags.get("adkim", "r").lower()
    aspf = tags.get("aspf", "r").lower()
    try:
        pct = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        pct = 100

    effective_policy = sp if is_subdomain else policy

    # Check SPF alignment (RFC 7489 Section 3.1.1)
    spf_aligned = spf_result.result == "pass" and domains_align(
        spf_result.domain, from_domain, aspf
    )

    # Check DKIM alignment (any passing DKIM signature whose d= aligns with From)
    dkim_aligned = False
    aligned_dkim_domain: Optional[str] = None
    for dkim in dkim_results:
        if dkim.result == "pass" and domains_align(dkim.domain, from_domain, adkim):
            dkim_aligned = True
            aligned_dkim_domain = dkim.domain
            break

    dmarc_pass = spf_aligned or dkim_aligned
    if dmarc_pass:
        disposition = "accept"
        reason_parts = []
        if spf_aligned:
            reason_parts.append(f"SPF passed & aligned ({spf_result.domain})")
        if dkim_aligned:
            reason_parts.append(f"DKIM passed & aligned ({aligned_dkim_domain})")
        reason = "DMARC PASS: " + "; ".join(reason_parts) + "."
    else:
        # Apply percentage sampling deterministically based on message_id/from_domain
        if pct == 0:
            disposition = "accept"
        elif pct < 100:
            bucket = int(
                hashlib.sha256(f"{from_domain}:{message_id}".encode("utf-8")).hexdigest()[:8],
                16,
            ) % 100
            sampled = bucket < pct
            if sampled:
                disposition = {"none": "accept", "quarantine": "quarantine", "reject": "reject"}.get(
                    effective_policy, "accept"
                )
            else:
                disposition = "accept"
        else:
            disposition = {"none": "accept", "quarantine": "quarantine", "reject": "reject"}.get(
                effective_policy, "accept"
            )

        reason = (
            f"DMARC FAIL (SPF={spf_result.result}, aligned={spf_aligned}; "
            f"DKIM aligned={dkim_aligned}). Policy p={effective_policy} -> disposition={disposition}."
        )

    return DMARCResult(
        result="pass" if dmarc_pass else "fail",
        disposition=disposition,
        from_domain=from_domain,
        policy=policy,
        subdomain_policy=sp,
        adkim=adkim,
        aspf=aspf,
        pct=pct,
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        aligned_dkim_domain=aligned_dkim_domain,
        dmarc_record=record,
        record_domain=record_domain,
        rua=tags.get("rua"),
        ruf=tags.get("ruf"),
        reason=reason,
    )


@dataclass
class DMARCRecordTelemetry:
    """Single message authentication record observed during DMARC monitoring/enforcement."""

    timestamp: str
    source_ip: str
    from_domain: str
    spf_domain: str
    spf_result: str
    dkim_domain: Optional[str]
    dkim_result: str
    dmarc_result: str
    disposition: str
    spf_aligned: bool
    dkim_aligned: bool


@dataclass
class DMARCLifecycleManager:
    """Manages the recommended DMARC rollout: Monitoring (p=none) -> Quarantine -> Reject."""

    domain: str
    dns_store: DNSZoneStore
    rua: Optional[str] = None
    ruf: Optional[str] = None
    observations: List[DMARCRecordTelemetry] = field(default_factory=list)

    def record_observation(
        self,
        source_ip: str,
        spf: SPFResult,
        dkim_list: List[DKIMVerificationResult],
        dmarc: DMARCResult,
    ) -> None:
        """Log telemetry for DMARC aggregate reporting & readiness validation."""
        passing_dkim = next((d for d in dkim_list if d.result == "pass"), dkim_list[0] if dkim_list else None)
        self.observations.append(
            DMARCRecordTelemetry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                source_ip=source_ip,
                from_domain=dmarc.from_domain,
                spf_domain=spf.domain,
                spf_result=spf.result,
                dkim_domain=passing_dkim.domain if passing_dkim else None,
                dkim_result=passing_dkim.result if passing_dkim else "none",
                dmarc_result=dmarc.result,
                disposition=dmarc.disposition,
                spf_aligned=dmarc.spf_aligned,
                dkim_aligned=dmarc.dkim_aligned,
            )
        )

    def get_alignment_summary(self) -> Dict[str, object]:
        """Compute alignment statistics to validate readiness for DMARC enforcement."""
        total = len(self.observations)
        passed = sum(1 for o in self.observations if o.dmarc_result == "pass")
        spf_aligned = sum(1 for o in self.observations if o.spf_aligned)
        dkim_aligned = sum(1 for o in self.observations if o.dkim_aligned)
        pass_rate = (passed / total) if total else 0.0
        current_record = self.dns_store.get_dmarc(self.domain) or ""
        tags = parse_dmarc_record(current_record) if current_record else {}
        return {
            "domain": self.domain,
            "current_policy": tags.get("p", "none"),
            "total_observed": total,
            "dmarc_pass_count": passed,
            "dmarc_fail_count": total - passed,
            "spf_aligned_count": spf_aligned,
            "dkim_aligned_count": dkim_aligned,
            "pass_rate": round(pass_rate, 4),
            "ready_for_enforcement": total > 0 and pass_rate >= 0.90,
        }

    def transition_policy(
        self,
        target_policy: str,
        adkim: str = "r",
        aspf: str = "r",
        pct: int = 100,
        force: bool = False,
    ) -> Dict[str, object]:
        """Transition DMARC policy (`none` -> `quarantine` -> `reject`) after checking alignment."""
        target = target_policy.lower()
        if target not in ("none", "quarantine", "reject"):
            raise ValueError("DMARC policy must be 'none', 'quarantine', or 'reject'.")

        summary = self.get_alignment_summary()
        if target in ("quarantine", "reject") and not force:
            # Verify that at least one aligned message passed during monitoring
            if summary["dmarc_pass_count"] == 0:
                raise RuntimeError(
                    "Cannot promote DMARC policy without at least one verified aligned message in monitoring."
                )

        sp = target
        record = self.dns_store.publish_dmarc(
            domain=self.domain,
            policy=target,
            subdomain_policy=sp,
            adkim=adkim,
            aspf=aspf,
            pct=pct,
            rua=self.rua,
            ruf=self.ruf,
        )
        return {
            "domain": self.domain,
            "new_policy": target,
            "adkim": adkim,
            "aspf": aspf,
            "pct": pct,
            "dmarc_record": record,
            "monitoring_summary": summary,
        }

    def generate_aggregate_xml(self, report_id: str = "gw-agg-001") -> str:
        """Render an RFC 7489 Section 7.2 / Appendix C DMARC aggregate XML report."""
        now_ts = int(datetime.now(timezone.utc).timestamp())
        current_record = self.dns_store.get_dmarc(self.domain) or ""
        tags = parse_dmarc_record(current_record) if current_record else {}

        records_xml: List[str] = []
        for obs in self.observations:
            disp_xml = {"accept": "none", "quarantine": "quarantine", "reject": "reject"}.get(
                obs.disposition, "none"
            )
            dkim_auth_xml = ""
            if obs.dkim_domain:
                dkim_auth_xml = (
                    f"      <dkim>\n"
                    f"        <domain>{xml_escape(obs.dkim_domain)}</domain>\n"
                    f"        <result>{xml_escape(obs.dkim_result)}</result>\n"
                    f"      </dkim>\n"
                )
            records_xml.append(
                "  <record>\n"
                "    <row>\n"
                f"      <source_ip>{xml_escape(obs.source_ip)}</source_ip>\n"
                "      <count>1</count>\n"
                "      <policy_evaluated>\n"
                f"        <disposition>{disp_xml}</disposition>\n"
                f"        <dkim>{'pass' if obs.dkim_aligned else 'fail'}</dkim>\n"
                f"        <spf>{'pass' if obs.spf_aligned else 'fail'}</spf>\n"
                "      </policy_evaluated>\n"
                "    </row>\n"
                "    <identifiers>\n"
                f"      <header_from>{xml_escape(obs.from_domain)}</header_from>\n"
                "    </identifiers>\n"
                "    <auth_results>\n"
                f"{dkim_auth_xml}"
                "      <spf>\n"
                f"        <domain>{xml_escape(obs.spf_domain)}</domain>\n"
                f"        <result>{xml_escape(obs.spf_result)}</result>\n"
                "      </spf>\n"
                "    </auth_results>\n"
                "  </record>"
            )

        return (
            '<?xml version="1.0" encoding="UTF-8" ?>\n'
            "<feedback>\n"
            "  <report_metadata>\n"
            "    <org_name>EmailAuth - a Secure Email Authentication Gateway with SPF, DKIM, and DMARC1</org_name>\n"
            f"    <email>{xml_escape(self.rua or 'postmaster@' + self.domain)}</email>\n"
            f"    <report_id>{xml_escape(report_id)}</report_id>\n"
            f"    <date_range><begin>{now_ts - 86400}</begin><end>{now_ts}</end></date_range>\n"
            "  </report_metadata>\n"
            "  <policy_published>\n"
            f"    <domain>{xml_escape(self.domain)}</domain>\n"
            f"    <adkim>{xml_escape(tags.get('adkim', 'r'))}</adkim>\n"
            f"    <aspf>{xml_escape(tags.get('aspf', 'r'))}</aspf>\n"
            f"    <p>{xml_escape(tags.get('p', 'none'))}</p>\n"
            f"    <sp>{xml_escape(tags.get('sp', tags.get('p', 'none')))}</sp>\n"
            f"    <pct>{xml_escape(tags.get('pct', '100'))}</pct>\n"
            "  </policy_published>\n"
            + "\n".join(records_xml)
            + "\n</feedback>\n"
        )
