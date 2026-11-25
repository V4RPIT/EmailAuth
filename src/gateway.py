"""End-to-end EmailAuth - a Secure Email Authentication Gateway with SPF, DKIM, and DMARC1 orchestrator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Dict, List, Optional

from .config import (
    BIND_ZONE_PATH,
    DNS_ZONE_PATH,
    KEYS_DIR,
    GatewayConfig,
)
from .crypto_rsa import (
    RSAPrivateKey,
    generate_rsa_keypair,
    parse_private_key_pem,
    save_keypair,
)
from .dkim import DKIMVerificationResult, normalize_crlf, sign_email, verify_dkim_signatures
from .dmarc import DMARCLifecycleManager, DMARCResult, evaluate_dmarc
from .dns_store import DNSZoneStore, normalize_domain
from .spf import SPFResult, evaluate_spf


@dataclass
class GatewayVerdict:
    """Result of inbound email gateway authentication and policy enforcement."""

    spf: SPFResult
    dkim: List[DKIMVerificationResult]
    dmarc: DMARCResult
    disposition: str  # accept, quarantine, reject
    stamped_email: str
    authentication_results_header: str
    received_spf_header: str


class SecureEmailGateway:
    """Coordinates DKIM key management, DNS provisioning, signing, and verification."""

    def __init__(
        self,
        config: Optional[GatewayConfig] = None,
        dns_store: Optional[DNSZoneStore] = None,
        keys_dir: Path = KEYS_DIR,
        gateway_hostname: str = "mx-gw.securemail.example",
    ) -> None:
        self.config = config or GatewayConfig()
        self.dns_store = dns_store or DNSZoneStore(DNS_ZONE_PATH)
        self.keys_dir = keys_dir
        self.gateway_hostname = gateway_hostname
        self.lifecycle = DMARCLifecycleManager(
            domain=self.config.domain,
            dns_store=self.dns_store,
            rua=self.config.rua_email,
            ruf=self.config.ruf_email,
        )

    @property
    def private_key_path(self) -> Path:
        return self.keys_dir / f"{self.config.dkim_selector}.private.pem"

    @property
    def public_key_path(self) -> Path:
        return self.keys_dir / f"{self.config.dkim_selector}.public.pem"

    def load_or_generate_keypair(self, regenerate: bool = False) -> RSAPrivateKey:
        """Load the configured DKIM RSA private key or generate a fresh 2048-bit pair."""
        if not regenerate and self.private_key_path.exists():
            return parse_private_key_pem(
                self.private_key_path.read_text(encoding="utf-8")
            )
        priv = generate_rsa_keypair(bits=self.config.key_bits)
        save_keypair(priv, self.private_key_path, self.public_key_path)
        return priv

    def provision_domain(
        self,
        regenerate_keys: bool = False,
        initial_dmarc_policy: str = "none",
        bind_output_path: Optional[Path] = BIND_ZONE_PATH,
    ) -> Dict[str, str]:
        """Configure SPF, DKIM public key, and initial DMARC DNS records."""
        priv = self.load_or_generate_keypair(regenerate=regenerate_keys)
        pub_b64 = priv.public_key().to_dkim_base64()

        spf_tokens = ["v=spf1"]
        for ip_cidr in self.config.authorized_ips:
            spf_tokens.append(f"ip4:{ip_cidr}")
        for ip6_cidr in self.config.authorized_ipv6:
            spf_tokens.append(f"ip6:{ip6_cidr}")
        spf_tokens.append("-all")
        spf_record = self.dns_store.publish_spf(self.config.domain, " ".join(spf_tokens))

        dkim_record = self.dns_store.publish_dkim(
            domain=self.config.domain,
            selector=self.config.dkim_selector,
            public_key_b64=pub_b64,
        )

        dmarc_record = self.dns_store.publish_dmarc(
            domain=self.config.domain,
            policy=initial_dmarc_policy,
            subdomain_policy=initial_dmarc_policy,
            adkim="r",
            aspf="r",
            pct=100,
            rua=self.config.rua_email,
            ruf=self.config.ruf_email,
        )

        # Also seed A/MX records for controlled simulation
        self.dns_store.set_records(
            self.config.domain,
            "MX",
            [f"10 {self.gateway_hostname}"],
        )
        self.dns_store.set_records(
            self.gateway_hostname,
            "A",
            [self.config.authorized_ips[0].split("/")[0]],
        )

        saved_json = self.dns_store.save()
        bind_text = self.dns_store.export_bind_zone(self.config.domain)
        if bind_output_path is not None:
            bind_output_path.parent.mkdir(parents=True, exist_ok=True)
            bind_output_path.write_text(bind_text, encoding="utf-8")

        return {
            "domain": self.config.domain,
            "selector": self.config.dkim_selector,
            "spf_record": spf_record,
            "dkim_record": dkim_record,
            "dmarc_record": dmarc_record,
            "private_key_path": str(self.private_key_path),
            "public_key_path": str(self.public_key_path),
            "dns_zone_path": str(saved_json),
            "bind_zone_path": str(bind_output_path) if bind_output_path else "",
        }

    def compose_and_sign(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        return_path: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> str:
        """Build an RFC 5322 message and sign it with the domain's DKIM key."""
        priv = self.load_or_generate_keypair(regenerate=False)
        domain = self.config.domain
        headers = [
            f"Return-Path: <{return_path or sender}>",
            f"From: {sender}",
            f"To: {recipient}",
            f"Subject: {subject}",
            f"Date: {formatdate(usegmt=True)}",
            f"Message-ID: {make_msgid(domain=domain)}",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=utf-8",
        ]
        if extra_headers:
            for k, v in extra_headers.items():
                headers.append(f"{k}: {v}")
        raw_msg = "\r\n".join(headers) + "\r\n\r\n" + body.rstrip("\r\n") + "\r\n"
        return sign_email(
            raw_msg,
            domain=domain,
            selector=self.config.dkim_selector,
            private_key=priv,
        )

    def sign_raw_message(self, raw_email: str) -> str:
        """Sign an existing raw RFC 5322 email using the active DKIM key."""
        priv = self.load_or_generate_keypair(regenerate=False)
        return sign_email(
            raw_email,
            domain=self.config.domain,
            selector=self.config.dkim_selector,
            private_key=priv,
        )

    def process_inbound(
        self,
        raw_email: str,
        client_ip: str,
        mail_from: str,
        helo_domain: Optional[str] = None,
        record_telemetry: bool = True,
    ) -> GatewayVerdict:
        """Run full inbound SPF -> DKIM -> DMARC pipeline and stamp headers."""
        spf_res = evaluate_spf(
            client_ip=client_ip,
            mail_from=mail_from,
            dns_store=self.dns_store,
            helo_domain=helo_domain,
        )
        dkim_res = verify_dkim_signatures(raw_email, self.dns_store)

        from_header = ""
        message_id = ""
        for line in normalize_crlf(raw_email).split("\r\n\r\n", 1)[0].split("\r\n"):
            if line.lower().startswith("from:"):
                from_header = line.split(":", 1)[1].strip()
            elif line.lower().startswith("message-id:"):
                message_id = line.split(":", 1)[1].strip()

        dmarc_res = evaluate_dmarc(
            from_header=from_header,
            spf_result=spf_res,
            dkim_results=dkim_res,
            dns_store=self.dns_store,
            message_id=message_id,
        )

        if record_telemetry and normalize_domain(dmarc_res.from_domain) == normalize_domain(
            self.config.domain
        ):
            self.lifecycle.record_observation(
                source_ip=client_ip,
                spf=spf_res,
                dkim_list=dkim_res,
                dmarc=dmarc_res,
            )

        # Build RFC 8601 Authentication-Results & RFC 7208 Received-SPF headers
        dkim_parts = []
        for d in dkim_res:
            if d.domain:
                dkim_parts.append(
                    f"dkim={d.result} header.d={d.domain} header.s={d.selector or '-'}"
                )
            else:
                dkim_parts.append(f"dkim={d.result}")

        auth_res_header = (
            f"Authentication-Results: {self.gateway_hostname};\r\n"
            f"\tspf={spf_res.result} smtp.mailfrom={spf_res.domain} (client-ip={spf_res.client_ip});\r\n"
            + "".join(f"\t{part};\r\n" for part in dkim_parts)
            + f"\tdmarc={dmarc_res.result} (p={dmarc_res.policy or 'none'} dis={dmarc_res.disposition}) "
            f"header.from={dmarc_res.from_domain}"
        )
        received_spf_header = (
            f"Received-SPF: {spf_res.result} ({self.gateway_hostname}: {spf_res.explanation}) "
            f"client-ip={spf_res.client_ip}; envelope-from={mail_from};"
        )
        received_stamp = (
            f"Received: from {helo_domain or spf_res.domain or 'unknown'} ([{spf_res.client_ip}]) "
            f"by {self.gateway_hostname} with ESMTP; {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')}"
        )

        stamped = (
            auth_res_header
            + "\r\n"
            + received_spf_header
            + "\r\n"
            + received_stamp
            + "\r\n"
            + normalize_crlf(raw_email)
        )

        return GatewayVerdict(
            spf=spf_res,
            dkim=dkim_res,
            dmarc=dmarc_res,
            disposition=dmarc_res.disposition,
            stamped_email=stamped,
            authentication_results_header=auth_res_header,
            received_spf_header=received_spf_header,
        )
