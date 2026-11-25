"""Command-line interface for EmailAuth - a Secure Email Authentication Gateway with SPF, DKIM, and DMARC1.

Supports:
- `setup`   : Generate RSA-2048 DKIM keys and publish SPF, DKIM, and DMARC (p=none) DNS records
- `sign`    : Sign an outgoing email with DKIM
- `analyze` : Parse a raw email or raw email header and output SPF/DKIM/DMARC summary
- `promote` : Validate monitoring alignment and promote DMARC policy (none -> quarantine -> reject)
- `demo`    : Run end-to-end controlled gateway simulation & generate verification artifacts
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List

# Allow running both as `python cli.py` inside email_auth_gateway/ and `python -m email_auth_gateway.cli`
_PKG_ROOT = Path(__file__).resolve().parent
if str(_PKG_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT.parent))

from email_auth_gateway.src.config import (  # noqa: E402
    BIND_ZONE_PATH,
    DNS_ZONE_PATH,
    REPORTS_DIR,
    SAMPLES_DIR,
    GatewayConfig,
)
from email_auth_gateway.src.dns_store import DNSZoneStore  # noqa: E402
from email_auth_gateway.src.gateway import SecureEmailGateway  # noqa: E402
from email_auth_gateway.src.header_parser import analyze_raw_email  # noqa: E402


def _build_gateway(zone_path: Path = DNS_ZONE_PATH) -> SecureEmailGateway:
    store = DNSZoneStore(zone_path=zone_path)
    return SecureEmailGateway(config=GatewayConfig(), dns_store=store)


def cmd_setup(args: argparse.Namespace) -> int:
    gw = _build_gateway()
    info = gw.provision_domain(
        regenerate_keys=args.regenerate_keys,
        initial_dmarc_policy=args.dmarc_policy,
        bind_output_path=BIND_ZONE_PATH,
    )
    print(json.dumps(info, indent=2))
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    gw = _build_gateway()
    if not gw.dns_store.get_dkim(gw.config.domain, gw.config.dkim_selector):
        gw.provision_domain(regenerate_keys=False)

    if args.input:
        raw = Path(args.input).read_bytes().decode("utf-8")
        signed = gw.sign_raw_message(raw)
    else:
        signed = gw.compose_and_sign(
            sender=args.sender,
            recipient=args.recipient,
            subject=args.subject,
            body=args.body,
        )

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(signed.encode("utf-8"))
        print(f"Signed message written to {out_path}")
    else:
        print(signed)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    if args.input:
        raw_text = Path(args.input).read_bytes().decode("utf-8")
    elif args.text:
        raw_text = args.text
    else:
        raw_text = sys.stdin.read()

    store = DNSZoneStore(zone_path=DNS_ZONE_PATH, allow_live_dns=args.live_dns)
    analysis = analyze_raw_email(
        raw_input=raw_text,
        dns_store=store,
        client_ip=args.client_ip,
        mail_from=args.mail_from,
    )

    if args.json:
        print(json.dumps(analysis.to_dict(), indent=2))
    else:
        print("=" * 72)
        print("EMAILAUTH - A SECURE EMAIL AUTHENTICATION GATEWAY WITH SPF, DKIM, AND DMARC1")
        print("=" * 72)
        print(analysis.summary_text)
        if analysis.received_hops:
            print("\nReceived Hop Chain:")
            for idx, hop in enumerate(analysis.received_hops, start=1):
                print(f"  {idx}. from={hop.from_host or '?'} by={hop.by_host or '?'} ip={hop.client_ip or '?'}")
        if analysis.upstream_auth_results:
            print("\nUpstream Authentication-Results:")
            for item in analysis.upstream_auth_results:
                print(
                    f"  - {item.authserv_id}: spf={item.spf or '-'} "
                    f"dkim={item.dkim or '-'} dmarc={item.dmarc or '-'}"
                )
        print("=" * 72)
    return 0


def cmd_promote(args: argparse.Namespace) -> int:
    gw = _build_gateway()
    res = gw.lifecycle.transition_policy(
        target_policy=args.policy,
        adkim=args.adkim,
        aspf=args.aspf,
        pct=args.pct,
        force=args.force,
    )
    gw.dns_store.save()
    BIND_ZONE_PATH.write_text(gw.dns_store.export_bind_zone(gw.config.domain), encoding="utf-8")
    print(json.dumps(res, indent=2))
    return 0


def run_controlled_demo(regenerate_keys: bool = False) -> Dict[str, Any]:
    """Execute the full controlled gateway simulation and save samples + reports."""
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    gw = SecureEmailGateway(config=GatewayConfig(), dns_store=DNSZoneStore(DNS_ZONE_PATH))

    # Stage 1: Provision domain with SPF, 2048-bit DKIM, and DMARC in monitoring mode (p=none)
    provision_info = gw.provision_domain(
        regenerate_keys=regenerate_keys,
        initial_dmarc_policy="none",
        bind_output_path=BIND_ZONE_PATH,
    )

    # Also seed an unaligned third-party relay domain to demonstrate alignment failure
    gw.dns_store.publish_spf("relay-mailer.example", "v=spf1 ip4:192.0.2.55 -all")
    gw.dns_store.save()

    # Stage 2: Sign outgoing test emails & validate alignment in DMARC monitoring mode (p=none)
    monitoring_messages = [
        ("notifications@securemail.example", "alice@partner.example", "Q4 Security Briefing", "All systems nominal."),
        ("billing@securemail.example", "finance@partner.example", "Invoice #4821", "Attached is your monthly statement."),
        ("security@securemail.example", "ops@partner.example", "Key Rotation Notice", "DKIM selector1 is active."),
    ]

    monitoring_results: List[Dict[str, Any]] = []
    signed_sample_email = ""
    for idx, (sender, rcpt, subj, body) in enumerate(monitoring_messages):
        signed_msg = gw.compose_and_sign(sender=sender, recipient=rcpt, subject=subj, body=body)
        if idx == 0:
            signed_sample_email = signed_msg
        verdict = gw.process_inbound(
            raw_email=signed_msg,
            client_ip="198.51.100.10",
            mail_from=sender,
            helo_domain="mx-gw.securemail.example",
        )
        monitoring_results.append(
            {
                "sender": sender,
                "spf": verdict.spf.result,
                "dkim": verdict.dkim[0].result,
                "dmarc": verdict.dmarc.result,
                "disposition": verdict.disposition,
                "spf_aligned": verdict.dmarc.spf_aligned,
                "dkim_aligned": verdict.dmarc.dkim_aligned,
            }
        )

    monitoring_summary = gw.lifecycle.get_alignment_summary()
    agg_xml = gw.lifecycle.generate_aggregate_xml(report_id="monitoring-phase-001")
    agg_xml_path = REPORTS_DIR / "dmarc_aggregate_report.xml"
    agg_xml_path.write_text(agg_xml, encoding="utf-8")

    # Stage 3: Promote DMARC from monitoring (p=none) -> quarantine -> reject enforcement
    quarantine_transition = gw.lifecycle.transition_policy("quarantine", adkim="r", aspf="r", pct=100)
    enforce_transition = gw.lifecycle.transition_policy("reject", adkim="s", aspf="s", pct=100)
    gw.dns_store.save()
    BIND_ZONE_PATH.write_text(gw.dns_store.export_bind_zone(gw.config.domain), encoding="utf-8")

    # Stage 4: Build 4 canonical test scenarios under strict DMARC enforcement (p=reject)
    # 4a. Legitimate signed & aligned email
    legit_verdict = gw.process_inbound(
        raw_email=signed_sample_email,
        client_ip="198.51.100.10",
        mail_from="notifications@securemail.example",
        helo_domain="mx-gw.securemail.example",
        record_telemetry=False,
    )
    legit_path = SAMPLES_DIR / "01_legitimate_aligned.eml"
    legit_path.write_bytes(legit_verdict.stamped_email.encode("utf-8"))

    # 4b. Spoofed unauthorized sender IP (no valid DKIM, SPF hard fail)
    spoof_raw = (
        "Return-Path: <ceo@securemail.example>\r\n"
        "From: CEO <ceo@securemail.example>\r\n"
        "To: payroll@securemail.example\r\n"
        "Subject: Urgent Wire Transfer Request\r\n"
        "Date: Wed, 25 Nov 2026 12:00:00 +0000\r\n"
        "Message-ID: <spoof-001@attacker.example>\r\n"
        "\r\n"
        "Please wire $45,000 immediately to account 998877.\r\n"
    )
    spoof_verdict = gw.process_inbound(
        raw_email=spoof_raw,
        client_ip="192.0.2.99",
        mail_from="ceo@securemail.example",
        helo_domain="botnet.attacker.example",
        record_telemetry=False,
    )
    spoof_path = SAMPLES_DIR / "02_spoofed_unauthorized_ip.eml"
    spoof_path.write_bytes(spoof_verdict.stamped_email.encode("utf-8"))

    # 4c. Tampered body after DKIM signing (authorized IP fails or unauthorized IP + broken DKIM)
    tampered_body_msg = signed_sample_email.replace(
        "All systems nominal.",
        "All systems compromised! Click http://evil.example/login",
    )
    tampered_verdict = gw.process_inbound(
        raw_email=tampered_body_msg,
        client_ip="192.0.2.99",
        mail_from="notifications@securemail.example",
        helo_domain="proxy.evil.example",
        record_telemetry=False,
    )
    tampered_path = SAMPLES_DIR / "03_tampered_dkim_body.eml"
    tampered_path.write_bytes(tampered_verdict.stamped_email.encode("utf-8"))

    # 4d. Unaligned relay phishing (SPF passes for relay-mailer.example, From spoofs securemail.example)
    unaligned_raw = (
        "Return-Path: <bounce@relay-mailer.example>\r\n"
        "From: \"IT Security (securemail.example)\" <security@securemail.example>\r\n"
        "Reply-To: attacker@evil-harvest.example\r\n"
        "To: employee@securemail.example\r\n"
        "Subject: Mandatory Password Reset\r\n"
        "Date: Wed, 25 Nov 2026 12:05:00 +0000\r\n"
        "Message-ID: <phish-004@relay-mailer.example>\r\n"
        "\r\n"
        "Reset your corporate SSO credentials at http://evil-harvest.example/sso\r\n"
    )
    unaligned_verdict = gw.process_inbound(
        raw_email=unaligned_raw,
        client_ip="192.0.2.55",
        mail_from="bounce@relay-mailer.example",
        helo_domain="relay-mailer.example",
        record_telemetry=False,
    )
    unaligned_path = SAMPLES_DIR / "04_unaligned_phishing_relay.eml"
    unaligned_path.write_bytes(unaligned_verdict.stamped_email.encode("utf-8"))

    scenarios = []
    for label, path, verdict in [
        ("Legitimate Signed & Aligned", legit_path, legit_verdict),
        ("Spoofed Unauthorized IP", spoof_path, spoof_verdict),
        ("Tampered Message Body (Broken DKIM)", tampered_path, tampered_verdict),
        ("Unaligned Phishing Relay", unaligned_path, unaligned_verdict),
    ]:
        parsed = analyze_raw_email(verdict.stamped_email, dns_store=gw.dns_store)
        scenarios.append(
            {
                "scenario": label,
                "sample_file": str(path.name),
                "spf_result": verdict.spf.result,
                "dkim_result": verdict.dkim[0].result,
                "dmarc_result": verdict.dmarc.result,
                "spf_aligned": verdict.dmarc.spf_aligned,
                "dkim_aligned": verdict.dmarc.dkim_aligned,
                "gateway_disposition": verdict.disposition,
                "header_analyzer_verdict": parsed.security_verdict,
                "risk_score": parsed.risk_score,
                "anomalies": parsed.anomalies,
            }
        )

    report = {
        "provision": provision_info,
        "monitoring_phase": {
            "policy": "none",
            "messages": monitoring_results,
            "summary": monitoring_summary,
            "aggregate_xml_report": str(agg_xml_path),
        },
        "policy_transitions": {
            "quarantine": quarantine_transition["dmarc_record"],
            "reject": enforce_transition["dmarc_record"],
        },
        "enforcement_scenarios": scenarios,
    }
    report_path = REPORTS_DIR / "gateway_verification_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def cmd_demo(args: argparse.Namespace) -> int:
    report = run_controlled_demo(regenerate_keys=args.regenerate_keys)
    print(json.dumps(report, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="EmailAuth - a Secure Email Authentication Gateway with SPF, DKIM, and DMARC1"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup", help="Provision DKIM keys and SPF/DKIM/DMARC DNS records")
    p_setup.add_argument("--regenerate-keys", action="store_true", help="Force new 2048-bit RSA keypair")
    p_setup.add_argument("--dmarc-policy", default="none", choices=["none", "quarantine", "reject"])
    p_setup.set_defaults(func=cmd_setup)

    p_sign = sub.add_parser("sign", help="Sign an outgoing email with DKIM")
    p_sign.add_argument("--input", help="Path to raw RFC 5322 email file")
    p_sign.add_argument("--output", help="Optional path to save signed email")
    p_sign.add_argument("--sender", default="notifications@securemail.example")
    p_sign.add_argument("--recipient", default="alice@partner.example")
    p_sign.add_argument("--subject", default="Authenticated Test Message")
    p_sign.add_argument("--body", default="This is a DKIM-signed test message.")
    p_sign.set_defaults(func=cmd_sign)

    p_analyze = sub.add_parser("analyze", help="Analyze raw email or headers for SPF/DKIM/DMARC")
    p_analyze.add_argument("--input", help="Path to raw email or header file (reads stdin if omitted)")
    p_analyze.add_argument("--text", help="Inline raw email/header string")
    p_analyze.add_argument("--client-ip", help="Override client IP for SPF check")
    p_analyze.add_argument("--mail-from", help="Override MAIL FROM / Return-Path for SPF check")
    p_analyze.add_argument("--live-dns", action="store_true", help="Allow live UDP DNS TXT lookup fallback")
    p_analyze.add_argument("--json", action="store_true", help="Output structured JSON")
    p_analyze.set_defaults(func=cmd_analyze)

    p_promote = sub.add_parser("promote", help="Promote DMARC policy after monitoring")
    p_promote.add_argument("--policy", required=True, choices=["none", "quarantine", "reject"])
    p_promote.add_argument("--adkim", default="s", choices=["r", "s"])
    p_promote.add_argument("--aspf", default="s", choices=["r", "s"])
    p_promote.add_argument("--pct", type=int, default=100)
    p_promote.add_argument("--force", action="store_true")
    p_promote.set_defaults(func=cmd_promote)

    p_demo = sub.add_parser("demo", help="Run full controlled gateway simulation & generate reports")
    p_demo.add_argument("--regenerate-keys", action="store_true")
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
