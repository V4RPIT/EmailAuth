"""Controlled authoritative DNS Zone Store for SPF, DKIM, and DMARC records.

Provides deterministic local DNS resolution for testing and demonstrating
email authentication in a controlled environment, BIND zone export, and an
optional pure-Python UDP DNS TXT fallback for live external lookups.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
import struct
from typing import Dict, List, Optional

from .config import DNS_ZONE_PATH


def normalize_domain(name: str) -> str:
    """Normalize a DNS name to lowercase without trailing dot."""
    return name.strip().rstrip(".").lower()


def _split_bind_txt(value: str, chunk_size: int = 250) -> str:
    """Format a TXT string into RFC 1035 <=255-byte quoted segments."""
    if len(value) <= chunk_size:
        return f'"{value}"'
    chunks = [value[i : i + chunk_size] for i in range(0, len(value), chunk_size)]
    return "( " + " ".join(f'"{c}"' for c in chunks) + " )"


class DNSZoneStore:
    """In-memory and JSON-persisted authoritative DNS record store."""

    def __init__(
        self,
        zone_path: Optional[Path] = None,
        allow_live_dns: bool = False,
        dns_server: str = "8.8.8.8",
    ) -> None:
        self.zone_path = zone_path
        self.allow_live_dns = allow_live_dns
        self.dns_server = dns_server
        # Structure: {fqdn: {"TXT": [...], "A": [...], "AAAA": [...], "MX": [...]}}
        self.records: Dict[str, Dict[str, List[str]]] = {}
        if zone_path is not None and zone_path.exists():
            self.load(zone_path)

    def load(self, path: Optional[Path] = None) -> None:
        """Load DNS records from a JSON zone file."""
        target = path or self.zone_path
        if target is None or not target.exists():
            return
        raw = json.loads(target.read_text(encoding="utf-8"))
        self.records = {
            normalize_domain(fqdn): {
                rtype.upper(): list(vals) for rtype, vals in rrsets.items()
            }
            for fqdn, rrsets in raw.get("records", {}).items()
        }

    def save(self, path: Optional[Path] = None) -> Path:
        """Persist DNS records to JSON."""
        target = path or self.zone_path or DNS_ZONE_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "description": "Controlled Authoritative DNS Zone Store for Secure Email Authentication Gateway",
            "records": self.records,
        }
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return target

    def set_records(self, fqdn: str, rdtype: str, values: List[str]) -> None:
        """Overwrite all records of `rdtype` for `fqdn`."""
        name = normalize_domain(fqdn)
        rtype = rdtype.upper()
        self.records.setdefault(name, {})[rtype] = list(values)

    def add_record(self, fqdn: str, rdtype: str, value: str) -> None:
        """Append a record value if not already present."""
        name = normalize_domain(fqdn)
        rtype = rdtype.upper()
        bucket = self.records.setdefault(name, {}).setdefault(rtype, [])
        if value not in bucket:
            bucket.append(value)

    def query(self, fqdn: str, rdtype: str) -> List[str]:
        """Query local zone first, then optionally fall back to live UDP DNS."""
        name = normalize_domain(fqdn)
        rtype = rdtype.upper()
        local_vals = self.records.get(name, {}).get(rtype, [])
        if local_vals:
            return list(local_vals)
        if self.allow_live_dns and rtype == "TXT":
            return _live_udp_txt_query(name, server=self.dns_server)
        return []

    def publish_spf(self, domain: str, spf_record: str) -> str:
        """Publish an SPF TXT record on `domain`, replacing any prior v=spf1 entry."""
        name = normalize_domain(domain)
        existing = [
            txt
            for txt in self.records.get(name, {}).get("TXT", [])
            if not txt.lower().startswith("v=spf1")
        ]
        existing.append(spf_record)
        self.set_records(name, "TXT", existing)
        return spf_record

    def publish_dkim(
        self,
        domain: str,
        selector: str,
        public_key_b64: str,
        key_type: str = "rsa",
        hash_algos: str = "sha256",
        flags: str = "",
    ) -> str:
        """Publish a DKIM public key TXT record at `<selector>._domainkey.<domain>`."""
        fqdn = f"{normalize_domain(selector)}._domainkey.{normalize_domain(domain)}"
        parts = [f"v=DKIM1", f"k={key_type}", f"h={hash_algos}"]
        if flags:
            parts.append(f"t={flags}")
        parts.append(f"p={public_key_b64}")
        record = "; ".join(parts)
        self.set_records(fqdn, "TXT", [record])
        return record

    def publish_dmarc(
        self,
        domain: str,
        policy: str = "none",
        subdomain_policy: Optional[str] = None,
        adkim: str = "r",
        aspf: str = "r",
        pct: int = 100,
        rua: Optional[str] = None,
        ruf: Optional[str] = None,
        fo: str = "1",
    ) -> str:
        """Publish a DMARC TXT record at `_dmarc.<domain>`."""
        fqdn = f"_dmarc.{normalize_domain(domain)}"
        parts = [
            "v=DMARC1",
            f"p={policy}",
            f"adkim={adkim}",
            f"aspf={aspf}",
            f"pct={pct}",
        ]
        if subdomain_policy:
            parts.append(f"sp={subdomain_policy}")
        if rua:
            parts.append(f"rua={rua}")
        if ruf:
            parts.append(f"ruf={ruf}")
        if fo:
            parts.append(f"fo={fo}")
        record = "; ".join(parts)
        self.set_records(fqdn, "TXT", [record])
        return record

    def get_spf(self, domain: str) -> Optional[str]:
        for txt in self.query(domain, "TXT"):
            if txt.lower().startswith("v=spf1"):
                return txt
        return None

    def get_dkim(self, domain: str, selector: str) -> Optional[str]:
        fqdn = f"{normalize_domain(selector)}._domainkey.{normalize_domain(domain)}"
        for txt in self.query(fqdn, "TXT"):
            if "p=" in txt:
                return txt
        return None

    def get_dmarc(self, domain: str) -> Optional[str]:
        fqdn = f"_dmarc.{normalize_domain(domain)}"
        for txt in self.query(fqdn, "TXT"):
            if txt.startswith("v=DMARC1"):
                return txt
        return None

    def export_bind_zone(self, origin: str) -> str:
        """Render records belonging to `origin` in BIND zone file format."""
        norm_origin = normalize_domain(origin)
        lines = [
            f"$ORIGIN {norm_origin}.",
            "$TTL 300",
            "",
        ]
        for fqdn in sorted(self.records.keys()):
            if fqdn != norm_origin and not fqdn.endswith(f".{norm_origin}"):
                continue
            owner = "@" if fqdn == norm_origin else fqdn[: -(len(norm_origin) + 1)]
            rrsets = self.records[fqdn]
            for rtype in sorted(rrsets.keys()):
                for val in rrsets[rtype]:
                    if rtype == "TXT":
                        lines.append(f"{owner:<28} IN TXT {_split_bind_txt(val)}")
                    else:
                        lines.append(f"{owner:<28} IN {rtype} {val}")
        lines.append("")
        return "\n".join(lines)


def _encode_dns_name(domain: str) -> bytes:
    parts = [p.encode("ascii") for p in normalize_domain(domain).split(".") if p]
    return b"".join(bytes([len(p)]) + p for p in parts) + b"\x00"


def _skip_dns_name(packet: bytes, offset: int) -> int:
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            return offset + 1
        if (length & 0xC0) == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def _live_udp_txt_query(
    fqdn: str, server: str = "8.8.8.8", timeout: float = 2.0
) -> List[str]:
    """Minimal RFC 1035 UDP DNS TXT query (used only when allow_live_dns=True)."""
    tx_id = 0x4D52
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(fqdn) + struct.pack("!HH", 16, 1)  # QTYPE=TXT, QCLASS=IN
    packet = header + question
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, 53))
            resp, _ = sock.recvfrom(4096)
    except OSError:
        return []

    if len(resp) < 12:
        return []
    _, _, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", resp[:12])
    pos = 12
    for _ in range(qdcount):
        pos = _skip_dns_name(resp, pos) + 4

    results: List[str] = []
    for _ in range(ancount):
        pos = _skip_dns_name(resp, pos)
        if pos + 10 > len(resp):
            break
        rtype, _, _, rdlength = struct.unpack("!HHIH", resp[pos : pos + 10])
        pos += 10
        rdata = resp[pos : pos + rdlength]
        pos += rdlength
        if rtype == 16:  # TXT
            txt_parts: List[str] = []
            idx = 0
            while idx < len(rdata):
                seg_len = rdata[idx]
                idx += 1
                txt_parts.append(rdata[idx : idx + seg_len].decode("utf-8", "replace"))
                idx += seg_len
            results.append("".join(txt_parts))
    return results
