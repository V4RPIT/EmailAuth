"""Raw email & header analyzer for SPF, DKIM, DMARC, and spoofing indicators.

Accepts either a full raw RFC 5322 email or raw email headers only, parses
upstream `Authentication-Results` / `Received-SPF` / `Received` hops, and
performs live SPF, DKIM, and DMARC verification against `DNSZoneStore`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from email.utils import parseaddr
import re
from typing import Any, Dict, List, Optional

from .dkim import DKIMVerificationResult, split_headers_and_body, verify_dkim_signatures
from .dmarc import (
    DMARCResult,
    domains_align,
    evaluate_dmarc,
    extract_from_domain,
)
from .dns_store import DNSZoneStore, normalize_domain
from .spf import SPFResult, evaluate_spf, extract_domain_from_address


_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_AUTH_RES_ITEM_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|bestguesspass)\b([^;]*)",
    re.IGNORECASE,
)


@dataclass
class ReceivedHop:
    """Single `Received:` header hop extracted in transit order."""

    raw: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    client_ip: Optional[str] = None


@dataclass
class UpstreamAuthHeader:
    """Parsed upstream `Authentication-Results` entry."""

    authserv_id: str
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    details: Dict[str, str] = field(default_factory=dict)
    raw: str = ""


@dataclass
class EmailHeaderAnalysis:
    """Comprehensive parsed authentication summary for a raw email/header."""

    from_header: str
    from_address: str
    from_domain: str
    return_path: str
    return_path_domain: str
    reply_to: str
    reply_to_domain: str
    subject: str
    date: str
    message_id: str
    inferred_client_ip: Optional[str]
    has_body: bool
    received_hops: List[ReceivedHop]
    upstream_auth_results: List[UpstreamAuthHeader]
    received_spf_headers: List[str]
    spf_evaluation: Optional[SPFResult]
    dkim_evaluations: List[DKIMVerificationResult]
    dmarc_evaluation: Optional[DMARCResult]
    anomalies: List[str]
    risk_score: int
    security_verdict: str  # TRUSTED, SUSPICIOUS, MALICIOUS_OR_SPOOFED, UNAUTHENTICATED
    summary_text: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _unfold_header_value(raw_val: str) -> str:
    return re.sub(r"\r?\n[ \t]+", " ", raw_val).strip()


def _parse_received_hop(raw_val: str) -> ReceivedHop:
    unfolded = _unfold_header_value(raw_val)
    from_match = re.search(r"\bfrom\s+([^\s(]+)", unfolded, re.IGNORECASE)
    by_match = re.search(r"\bby\s+([^\s(;]+)", unfolded, re.IGNORECASE)
    ip_match = _IPV4_RE.search(unfolded) or _IPV6_RE.search(unfolded)
    return ReceivedHop(
        raw=unfolded,
        from_host=from_match.group(1) if from_match else None,
        by_host=by_match.group(1) if by_match else None,
        client_ip=ip_match.group(0) if ip_match else None,
    )


def _parse_authentication_results(raw_val: str) -> UpstreamAuthHeader:
    unfolded = _unfold_header_value(raw_val)
    parts = [p.strip() for p in unfolded.split(";") if p.strip()]
    authserv_id = parts[0] if parts else "unknown"
    entry = UpstreamAuthHeader(authserv_id=authserv_id, raw=unfolded)
    for match in _AUTH_RES_ITEM_RE.finditer(unfolded):
        proto = match.group(1).lower()
        outcome = match.group(2).lower()
        tail = match.group(3).strip()
        setattr(entry, proto, outcome)
        if tail:
            entry.details[proto] = tail
    return entry


def analyze_raw_email(
    raw_input: str,
    dns_store: Optional[DNSZoneStore] = None,
    client_ip: Optional[str] = None,
    mail_from: Optional[str] = None,
) -> EmailHeaderAnalysis:
    """Parse raw email/headers and produce a complete SPF/DKIM/DMARC security summary."""
    parsed_headers, body = split_headers_and_body(raw_input)
    has_body = bool(body.strip())

    # Map first occurrence of single-value headers and collect multi-value headers
    header_map: Dict[str, str] = {}
    received_raw: List[str] = []
    auth_res_raw: List[str] = []
    received_spf_raw: List[str] = []

    for name, val, _ in parsed_headers:
        lower = name.lower()
        unfolded = _unfold_header_value(val)
        if lower not in header_map:
            header_map[lower] = unfolded
        if lower == "received":
            received_raw.append(val)
        elif lower == "authentication-results":
            auth_res_raw.append(val)
        elif lower == "received-spf":
            received_spf_raw.append(unfolded)

    from_header = header_map.get("from", "")
    from_display, from_addr = parseaddr(from_header)
    from_domain = extract_from_domain(from_header)

    return_path = header_map.get("return-path", "") or (mail_from or "")
    _, rp_addr = parseaddr(return_path)
    rp_domain = extract_domain_from_address(rp_addr or return_path)

    reply_to = header_map.get("reply-to", "")
    _, rt_addr = parseaddr(reply_to)
    rt_domain = extract_domain_from_address(rt_addr) if rt_addr else ""

    received_hops = [_parse_received_hop(r) for r in received_raw]
    upstream_auth = [_parse_authentication_results(a) for a in auth_res_raw]

    # Infer originating client IP from explicit param or bottom-most Received hop
    inferred_ip = client_ip
    if not inferred_ip:
        for hop in reversed(received_hops):
            if hop.client_ip:
                inferred_ip = hop.client_ip
                break

    # Run active DNS/crypto checks when DNS store is available
    spf_eval: Optional[SPFResult] = None
    dkim_evals: List[DKIMVerificationResult] = []
    dmarc_eval: Optional[DMARCResult] = None

    if dns_store is not None:
        effective_mail_from = rp_addr or return_path or from_addr
        if inferred_ip and effective_mail_from:
            spf_eval = evaluate_spf(
                client_ip=inferred_ip,
                mail_from=effective_mail_from,
                dns_store=dns_store,
            )

        dkim_evals = verify_dkim_signatures(raw_input, dns_store)

        # If header-only input (no body) caused body-hash mismatch, mark note clearly
        if not has_body:
            for d in dkim_evals:
                if d.body_hash_valid is False:
                    d.reason = (
                        "Header-only input provided (no email body): DKIM body hash (bh=) "
                        "cannot be verified without the full message body."
                    )

        if spf_eval is not None or any(d.result != "none" for d in dkim_evals):
            effective_spf = spf_eval or SPFResult(
                result="none",
                domain=rp_domain or from_domain,
                client_ip=inferred_ip or "unknown",
                explanation="Client IP unavailable in headers for live SPF check.",
            )
            dmarc_eval = evaluate_dmarc(
                from_header=from_header,
                spf_result=effective_spf,
                dkim_results=dkim_evals,
                dns_store=dns_store,
                message_id=header_map.get("message-id", ""),
            )

    # Anomaly detection & risk scoring
    anomalies: List[str] = []
    risk_score = 0

    if not from_domain:
        anomalies.append("Missing or malformed RFC 5322 'From' header.")
        risk_score += 35

    if from_display and "@" in from_display:
        display_domain = extract_domain_from_address(from_display)
        if display_domain and from_domain and display_domain != from_domain:
            anomalies.append(
                f"Display-name spoofing detected: display text mentions '{from_display}' "
                f"while actual sender address is '{from_addr}'."
            )
            risk_score += 35

    if rp_domain and from_domain and not domains_align(rp_domain, from_domain, "r"):
        anomalies.append(
            f"Envelope Return-Path domain ({rp_domain}) does not align with From domain ({from_domain})."
        )
        risk_score += 20

    if rt_domain and from_domain and not domains_align(rt_domain, from_domain, "r"):
        anomalies.append(
            f"Reply-To domain ({rt_domain}) differs from From domain ({from_domain}) — potential phishing/BEC redirect."
        )
        risk_score += 25

    # Incorporate live SPF/DKIM/DMARC evaluation into risk score
    if spf_eval is not None:
        if spf_eval.result in ("fail", "softfail"):
            anomalies.append(f"SPF {spf_eval.result.upper()}: {spf_eval.explanation}")
            risk_score += 30 if spf_eval.result == "fail" else 15
        elif spf_eval.result in ("none", "permerror"):
            anomalies.append(f"SPF {spf_eval.result.upper()}: {spf_eval.explanation}")
            risk_score += 10

    for d in dkim_evals:
        if d.result == "fail" and not (not has_body and d.body_hash_valid is False):
            anomalies.append(f"DKIM FAIL ({d.domain or 'unknown'}): {d.reason}")
            risk_score += 35
        elif d.result == "none":
            anomalies.append("Message is not DKIM-signed.")
            risk_score += 15
        elif d.result == "permerror":
            anomalies.append(f"DKIM PERMERROR: {d.reason}")
            risk_score += 15

    if dmarc_eval is not None:
        if dmarc_eval.result == "fail":
            anomalies.append(f"DMARC FAIL ({dmarc_eval.disposition.upper()}): {dmarc_eval.reason}")
            risk_score += 35 if dmarc_eval.policy == "reject" else 25
        elif dmarc_eval.result == "none":
            anomalies.append(f"No DMARC policy published for {from_domain}.")
            risk_score += 10
    elif upstream_auth:
        # Evaluate upstream Authentication-Results when no local DNS evaluation was possible
        latest = upstream_auth[0]
        if latest.spf in ("fail", "softfail"):
            anomalies.append(f"Upstream Authentication-Results reports spf={latest.spf}.")
            risk_score += 25
        if latest.dkim == "fail":
            anomalies.append("Upstream Authentication-Results reports dkim=fail.")
            risk_score += 30
        if latest.dmarc == "fail":
            anomalies.append("Upstream Authentication-Results reports dmarc=fail.")
            risk_score += 35

    risk_score = min(100, risk_score)

    if risk_score >= 55 or (dmarc_eval and dmarc_eval.disposition == "reject"):
        verdict = "MALICIOUS_OR_SPOOFED"
    elif risk_score >= 25 or (dmarc_eval and dmarc_eval.disposition == "quarantine"):
        verdict = "SUSPICIOUS"
    elif dmarc_eval and dmarc_eval.result == "pass":
        verdict = "TRUSTED"
    elif upstream_auth and upstream_auth[0].dmarc == "pass":
        verdict = "TRUSTED"
    else:
        verdict = "UNAUTHENTICATED"

    dkim_summary_str = (
        ", ".join(f"{d.result}({d.domain or 'none'})" for d in dkim_evals)
        if dkim_evals
        else "not-checked"
    )
    summary_lines = [
        f"Verdict       : {verdict} (Risk Score: {risk_score}/100)",
        f"From          : {from_header or '(missing)'} [domain={from_domain or 'n/a'}]",
        f"Return-Path   : {return_path or '(missing)'} [domain={rp_domain or 'n/a'}]",
        f"Client IP     : {inferred_ip or '(not found)'}",
        f"SPF           : {spf_eval.result if spf_eval else (upstream_auth[0].spf if upstream_auth else 'not-checked')}",
        f"DKIM          : {dkim_summary_str}",
        f"DMARC         : {dmarc_eval.result if dmarc_eval else (upstream_auth[0].dmarc if upstream_auth else 'not-checked')}"
        + (f" [disposition={dmarc_eval.disposition}, spf_aligned={dmarc_eval.spf_aligned}, dkim_aligned={dmarc_eval.dkim_aligned}]" if dmarc_eval else ""),
    ]
    if anomalies:
        summary_lines.append("Security Findings:")
        for item in anomalies:
            summary_lines.append(f"  - {item}")

    return EmailHeaderAnalysis(
        from_header=from_header,
        from_address=from_addr,
        from_domain=from_domain,
        return_path=return_path,
        return_path_domain=rp_domain,
        reply_to=reply_to,
        reply_to_domain=rt_domain,
        subject=header_map.get("subject", ""),
        date=header_map.get("date", ""),
        message_id=header_map.get("message-id", ""),
        inferred_client_ip=inferred_ip,
        has_body=has_body,
        received_hops=received_hops,
        upstream_auth_results=upstream_auth,
        received_spf_headers=received_spf_raw,
        spf_evaluation=spf_eval,
        dkim_evaluations=dkim_evals,
        dmarc_evaluation=dmarc_eval,
        anomalies=anomalies,
        risk_score=risk_score,
        security_verdict=verdict,
        summary_text="\n".join(summary_lines),
    )
