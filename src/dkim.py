"""RFC 6376 DomainKeys Identified Mail (DKIM) signing and verification.

Supports:
- `rsa-sha256` signing and verification using PKCS#1 v1.5
- `relaxed/relaxed`, `relaxed/simple`, `simple/relaxed`, `simple/simple` canonicalization
- Header unfolding, whitespace collapsing, trailing empty line trimming
- Multi-signature verification against DNS `<selector>._domainkey.<domain>` TXT records
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import re
from typing import Dict, List, Optional, Tuple

from .crypto_rsa import (
    RSAPrivateKey,
    parse_public_key_dkim_b64,
    sign_rsa_sha256,
    verify_rsa_sha256,
)
from .dns_store import DNSZoneStore, normalize_domain


DEFAULT_SIGNED_HEADERS = [
    "From",
    "To",
    "Subject",
    "Date",
    "Message-ID",
    "MIME-Version",
    "Content-Type",
]


@dataclass
class DKIMVerificationResult:
    """Verification result for a single DKIM-Signature header."""

    result: str  # pass, fail, permerror, temperror, neutral, none
    domain: Optional[str] = None
    selector: Optional[str] = None
    algorithm: Optional[str] = None
    canonicalization: Optional[str] = None
    signed_headers: List[str] = field(default_factory=list)
    body_hash_valid: Optional[bool] = None
    signature_valid: Optional[bool] = None
    reason: str = ""
    raw_tag_map: Dict[str, str] = field(default_factory=dict)


def normalize_crlf(raw_email: str) -> str:
    """Convert any LF, CR, or Windows-mangled CR+CRLF line endings to RFC 5322 CRLF."""
    collapsed = re.sub(r"\r+\n", "\n", raw_email)
    return collapsed.replace("\r", "\n").replace("\n", "\r\n")


def split_headers_and_body(raw_email: str) -> Tuple[List[Tuple[str, str, str]], str]:
    """Split a raw RFC 5322 message into `(name, value, raw_header_block)` tuples and body.

    Preserves folded lines in `raw_header_block` (without the terminating CRLF)
    and unfolded/raw value in `value`.
    """
    normalized = normalize_crlf(raw_email)
    if "\r\n\r\n" in normalized:
        header_section, body = normalized.split("\r\n\r\n", 1)
    else:
        header_section, body = normalized, ""

    raw_blocks: List[str] = []
    for line in header_section.split("\r\n"):
        if not line:
            continue
        if line[0] in (" ", "\t") and raw_blocks:
            raw_blocks[-1] += "\r\n" + line
        else:
            raw_blocks.append(line)

    parsed_headers: List[Tuple[str, str, str]] = []
    for block in raw_blocks:
        if ":" not in block:
            continue
        name, value = block.split(":", 1)
        parsed_headers.append((name.strip(), value, block))
    return parsed_headers, body


def canonicalize_body(body: str, mode: str) -> bytes:
    """Canonicalize message body according to RFC 6376 `simple` or `relaxed`."""
    mode = mode.lower()
    if mode not in ("simple", "relaxed"):
        raise ValueError(f"Unsupported body canonicalization mode: {mode}")

    lines = body.split("\r\n") if body else []
    if mode == "relaxed":
        proc_lines = [re.sub(r"[ \t]+", " ", line.rstrip(" \t")) for line in lines]
        while proc_lines and proc_lines[-1] == "":
            proc_lines.pop()
        if not proc_lines:
            return b""
        return ("\r\n".join(proc_lines) + "\r\n").encode("utf-8")

    # simple canonicalization
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        return b"\r\n"
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def canonicalize_header(name: str, value: str, raw_block: str, mode: str) -> str:
    """Canonicalize a single header line (without trailing CRLF)."""
    mode = mode.lower()
    if mode == "simple":
        return raw_block
    if mode == "relaxed":
        unfolded = re.sub(r"\r\n[ \t]+", " ", value)
        collapsed = re.sub(r"[ \t]+", " ", unfolded).strip(" \t")
        return f"{name.lower()}:{collapsed}"
    raise ValueError(f"Unsupported header canonicalization mode: {mode}")


def _parse_tag_list(raw_value: str) -> Dict[str, str]:
    """Parse semicolon-delimited `tag=value` pairs used in DKIM headers and DNS TXT."""
    unfolded = re.sub(r"\r?\n[ \t]*", "", raw_value)
    tags: Dict[str, str] = {}
    for item in unfolded.split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        key, val = item.split("=", 1)
        tags[key.strip()] = val.strip()
    return tags


def _strip_b_tag_value(raw_dkim_block: str) -> str:
    """Blank out the `b=` tag value while preserving surrounding structure."""
    # Match `b=` (preceded by start, `;`, or whitespace after `:`) up to `;` or end
    return re.sub(
        r"((?:^|[:;\s])b\s*=\s*)([^;]*)",
        r"\1",
        raw_dkim_block,
        count=1,
        flags=re.IGNORECASE | re.DOTALL,
    )


def _fold_dkim_signature(tag_pairs: List[str]) -> str:
    """Format a clean, folded `DKIM-Signature` header block (without trailing CRLF)."""
    header = "DKIM-Signature: " + "; ".join(tag_pairs[:4])
    current_line = " "
    for pair in tag_pairs[4:]:
        candidate = (current_line + pair + "; ") if current_line.strip() else ("\t" + pair + "; ")
        if len(candidate) > 76 and current_line.strip():
            header += ";\r\n" + current_line.rstrip()
            current_line = "\t" + pair
        else:
            current_line = (current_line + "; " + pair) if current_line.strip() else ("\t" + pair)
    if current_line.strip():
        header += ";\r\n" + current_line.rstrip()
    return header


def sign_email(
    raw_email: str,
    domain: str,
    selector: str,
    private_key: RSAPrivateKey,
    canonicalization: str = "relaxed/relaxed",
    headers_to_sign: Optional[List[str]] = None,
) -> str:
    """Sign an RFC 5322 raw email and prepend a `DKIM-Signature` header."""
    if "/" in canonicalization:
        hdr_canon, body_canon = [p.strip().lower() for p in canonicalization.split("/", 1)]
    else:
        hdr_canon, body_canon = canonicalization.strip().lower(), "simple"

    norm_domain = normalize_domain(domain)
    norm_selector = normalize_domain(selector)
    parsed_headers, body = split_headers_and_body(raw_email)

    # Select headers present in the message (RFC 6376 recommends signing From)
    wanted = [h.lower() for h in (headers_to_sign or DEFAULT_SIGNED_HEADERS)]
    available_names = {h[0].lower() for h in parsed_headers}
    chosen_lower = [h for h in wanted if h in available_names]
    if "from" not in chosen_lower and "from" in available_names:
        chosen_lower.insert(0, "from")

    # Compute body hash `bh=`
    canon_body = canonicalize_body(body, body_canon)
    bh_b64 = base64.b64encode(hashlib.sha256(canon_body).digest()).decode("ascii")

    # Build unsigned DKIM-Signature header template (empty `b=`)
    tag_pairs = [
        "v=1",
        "a=rsa-sha256",
        f"c={hdr_canon}/{body_canon}",
        f"d={norm_domain}",
        f"s={norm_selector}",
        f"h={':'.join(chosen_lower)}",
        f"bh={bh_b64}",
        "b=",
    ]
    unsigned_block = _fold_dkim_signature(tag_pairs)
    _, unsigned_val = unsigned_block.split(":", 1)

    # Gather headers from bottom to top per RFC 6376 Section 5.4
    by_name: Dict[str, List[Tuple[str, str, str]]] = {}
    for entry in parsed_headers:
        by_name.setdefault(entry[0].lower(), []).append(entry)
    consumed_idx: Dict[str, int] = {
        name: len(entries) - 1 for name, entries in by_name.items()
    }

    signing_parts: List[str] = []
    for h_name in chosen_lower:
        idx = consumed_idx.get(h_name, -1)
        if idx >= 0:
            name, val, raw_block = by_name[h_name][idx]
            consumed_idx[h_name] = idx - 1
            signing_parts.append(canonicalize_header(name, val, raw_block, hdr_canon) + "\r\n")

    signing_parts.append(
        canonicalize_header("DKIM-Signature", unsigned_val, unsigned_block, hdr_canon)
    )
    signing_input = "".join(signing_parts).encode("utf-8")

    signature = sign_rsa_sha256(signing_input, private_key)
    sig_b64 = base64.b64encode(signature).decode("ascii")
    # Wrap base64 neatly across lines inside `b=`
    wrapped_b64 = "\r\n\t ".join(sig_b64[i : i + 64] for i in range(0, len(sig_b64), 64))
    signed_block = unsigned_block[:-2] + f"b={wrapped_b64}"

    normalized = normalize_crlf(raw_email)
    return signed_block + "\r\n" + normalized


def verify_dkim_signatures(
    raw_email: str, dns_store: DNSZoneStore
) -> List[DKIMVerificationResult]:
    """Verify all `DKIM-Signature` headers present in `raw_email`."""
    parsed_headers, body = split_headers_and_body(raw_email)
    dkim_headers = [h for h in parsed_headers if h[0].lower() == "dkim-signature"]
    if not dkim_headers:
        return [
            DKIMVerificationResult(
                result="none",
                reason="Message contains no DKIM-Signature header.",
            )
        ]

    results: List[DKIMVerificationResult] = []
    for _, raw_val, raw_block in dkim_headers:
        tags = _parse_tag_list(raw_val)
        domain = normalize_domain(tags.get("d", "")) if tags.get("d") else None
        selector = normalize_domain(tags.get("s", "")) if tags.get("s") else None
        algo = tags.get("a", "").lower()
        canon = tags.get("c", "simple/simple").lower()
        hdr_canon, body_canon = (
            [p.strip() for p in canon.split("/", 1)]
            if "/" in canon
            else [canon, "simple"]
        )
        signed_headers = [
            h.strip().lower() for h in tags.get("h", "").split(":") if h.strip()
        ]

        if tags.get("v", "1") != "1":
            results.append(
                DKIMVerificationResult(
                    result="permerror",
                    domain=domain,
                    selector=selector,
                    algorithm=algo,
                    canonicalization=canon,
                    reason=f"Unsupported DKIM version v={tags.get('v')}.",
                    raw_tag_map=tags,
                )
            )
            continue

        if not domain or not selector or "bh" not in tags or "b" not in tags or not signed_headers:
            results.append(
                DKIMVerificationResult(
                    result="permerror",
                    domain=domain,
                    selector=selector,
                    algorithm=algo,
                    canonicalization=canon,
                    signed_headers=signed_headers,
                    reason="DKIM-Signature missing required tag(s): d, s, h, bh, or b.",
                    raw_tag_map=tags,
                )
            )
            continue

        if "from" not in signed_headers:
            results.append(
                DKIMVerificationResult(
                    result="permerror",
                    domain=domain,
                    selector=selector,
                    algorithm=algo,
                    canonicalization=canon,
                    signed_headers=signed_headers,
                    reason="RFC 6376 requires the 'From' header to be covered in h=.",
                    raw_tag_map=tags,
                )
            )
            continue

        if algo != "rsa-sha256":
            results.append(
                DKIMVerificationResult(
                    result="permerror",
                    domain=domain,
                    selector=selector,
                    algorithm=algo,
                    canonicalization=canon,
                    signed_headers=signed_headers,
                    reason=f"Unsupported algorithm '{algo}' (expected rsa-sha256).",
                    raw_tag_map=tags,
                )
            )
            continue

        # 1. Verify body hash (`bh=`)
        try:
            canon_body = canonicalize_body(body, body_canon)
        except ValueError as exc:
            results.append(
                DKIMVerificationResult(
                    result="permerror",
                    domain=domain,
                    selector=selector,
                    algorithm=algo,
                    canonicalization=canon,
                    signed_headers=signed_headers,
                    reason=str(exc),
                    raw_tag_map=tags,
                )
            )
            continue

        expected_bh = base64.b64encode(hashlib.sha256(canon_body).digest()).decode("ascii")
        claimed_bh = "".join(tags["bh"].split())
        if expected_bh != claimed_bh:
            results.append(
                DKIMVerificationResult(
                    result="fail",
                    domain=domain,
                    selector=selector,
                    algorithm=algo,
                    canonicalization=canon,
                    signed_headers=signed_headers,
                    body_hash_valid=False,
                    signature_valid=False,
                    reason="DKIM body hash mismatch (message body was altered after signing).",
                    raw_tag_map=tags,
                )
            )
            continue

        # 2. Fetch DNS public key at <selector>._domainkey.<domain>
        dns_txt = dns_store.get_dkim(domain, selector)
        if not dns_txt:
            results.append(
                DKIMVerificationResult(
                    result="permerror",
                    domain=domain,
                    selector=selector,
                    algorithm=algo,
                    canonicalization=canon,
                    signed_headers=signed_headers,
                    body_hash_valid=True,
                    reason=f"No DKIM TXT record found at {selector}._domainkey.{domain}.",
                    raw_tag_map=tags,
                )
            )
            continue

        dns_tags = _parse_tag_list(dns_txt)
        p_val = dns_tags.get("p", "")
        if not p_val:
            results.append(
                DKIMVerificationResult(
                    result="fail",
                    domain=domain,
                    selector=selector,
                    algorithm=algo,
                    canonicalization=canon,
                    signed_headers=signed_headers,
                    body_hash_valid=True,
                    signature_valid=False,
                    reason="DKIM public key has been revoked (empty p= tag in DNS).",
                    raw_tag_map=tags,
                )
            )
            continue

        try:
            public_key = parse_public_key_dkim_b64(p_val)
            signature_bytes = base64.b64decode("".join(tags["b"].split()))
        except Exception as exc:
            results.append(
                DKIMVerificationResult(
                    result="permerror",
                    domain=domain,
                    selector=selector,
                    algorithm=algo,
                    canonicalization=canon,
                    signed_headers=signed_headers,
                    body_hash_valid=True,
                    reason=f"Malformed DKIM public key or signature Base64: {exc}",
                    raw_tag_map=tags,
                )
            )
            continue

        # 3. Reconstruct signing input
        by_name: Dict[str, List[Tuple[str, str, str]]] = {}
        for entry in parsed_headers:
            by_name.setdefault(entry[0].lower(), []).append(entry)
        consumed_idx: Dict[str, int] = {
            name: len(entries) - 1 for name, entries in by_name.items()
        }

        signing_parts: List[str] = []
        for h_name in signed_headers:
            idx = consumed_idx.get(h_name, -1)
            if idx >= 0:
                name, val, h_block = by_name[h_name][idx]
                consumed_idx[h_name] = idx - 1
                signing_parts.append(canonicalize_header(name, val, h_block, hdr_canon) + "\r\n")

        stripped_block = _strip_b_tag_value(raw_block)
        _, stripped_val = stripped_block.split(":", 1)
        signing_parts.append(
            canonicalize_header("DKIM-Signature", stripped_val, stripped_block, hdr_canon)
        )
        signing_input = "".join(signing_parts).encode("utf-8")

        sig_ok = verify_rsa_sha256(signing_input, signature_bytes, public_key)
        results.append(
            DKIMVerificationResult(
                result="pass" if sig_ok else "fail",
                domain=domain,
                selector=selector,
                algorithm=algo,
                canonicalization=canon,
                signed_headers=signed_headers,
                body_hash_valid=True,
                signature_valid=sig_ok,
                reason=(
                    f"Valid RSA-SHA256 DKIM signature for {domain} (selector={selector})."
                    if sig_ok
                    else "RSA signature verification failed (headers altered or wrong key)."
                ),
                raw_tag_map=tags,
            )
        )
    return results
