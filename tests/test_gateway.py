"""Automated test suite for the Secure Email Authentication Gateway."""

from __future__ import annotations

from pathlib import Path
import sys
import xml.etree.ElementTree as ET

from fastapi.testclient import TestClient
import pytest

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT.parent))

from email_auth_gateway.cli import main as cli_main, run_controlled_demo  # noqa: E402
from email_auth_gateway.src.config import GatewayConfig  # noqa: E402
from email_auth_gateway.src.crypto_rsa import (  # noqa: E402
    generate_rsa_keypair,
    parse_private_key_pem,
    parse_public_key_dkim_b64,
    sign_rsa_sha256,
    verify_rsa_sha256,
)
from email_auth_gateway.src.dkim import sign_email, verify_dkim_signatures  # noqa: E402
from email_auth_gateway.src.dmarc import (  # noqa: E402
    DMARCLifecycleManager,
    domains_align,
    evaluate_dmarc,
    get_organizational_domain,
)
from email_auth_gateway.src.dns_store import DNSZoneStore  # noqa: E402
from email_auth_gateway.src.gateway import SecureEmailGateway  # noqa: E402
from email_auth_gateway.src.header_parser import analyze_raw_email  # noqa: E402
from email_auth_gateway.src.spf import SPFResult, evaluate_spf  # noqa: E402
from email_auth_gateway.web_app import app  # noqa: E402


@pytest.fixture(scope="module")
def rsa_2048_keypair():
    return generate_rsa_keypair(bits=2048)


def test_rsa_2048_keygen_serialization_and_signing(rsa_2048_keypair) -> None:
    priv = rsa_2048_keypair
    assert priv.key_size_bits == 2048

    pem_priv = priv.to_pem()
    loaded_priv = parse_private_key_pem(pem_priv)
    assert loaded_priv.n == priv.n
    assert loaded_priv.d == priv.d

    dkim_b64 = priv.public_key().to_dkim_base64()
    loaded_pub = parse_public_key_dkim_b64(dkim_b64)
    assert loaded_pub.n == priv.n
    assert loaded_pub.e == 65537

    msg = b"dkim-signing-payload"
    sig = sign_rsa_sha256(msg, loaded_priv)
    assert verify_rsa_sha256(msg, sig, loaded_pub) is True
    assert verify_rsa_sha256(b"tampered-payload", sig, loaded_pub) is False


def test_spf_mechanisms_and_lookup_limit() -> None:
    store = DNSZoneStore()
    store.publish_spf("corp.example", "v=spf1 ip4:198.51.100.10 ip4:203.0.113.0/24 include:esp.example -all")
    store.publish_spf("esp.example", "v=spf1 ip4:192.0.2.40 ~all")

    assert evaluate_spf("198.51.100.10", "alerts@corp.example", store).result == "pass"
    assert evaluate_spf("203.0.113.77", "alerts@corp.example", store).result == "pass"
    assert evaluate_spf("192.0.2.40", "alerts@corp.example", store).result == "pass"
    assert evaluate_spf("192.0.2.99", "alerts@corp.example", store).result == "fail"

    # Verify RFC 7208 10-DNS-lookup limit enforcement
    too_many = " ".join(f"include:sub{i}.example" for i in range(12))
    store.publish_spf("heavy.example", f"v=spf1 {too_many} -all")
    for i in range(12):
        store.publish_spf(f"sub{i}.example", "v=spf1 ip4:10.0.0.1 ~all")
    res = evaluate_spf("192.0.2.1", "user@heavy.example", store)
    assert res.result == "permerror"
    assert res.dns_lookups > 10


def test_dkim_sign_verify_and_tamper_detection(rsa_2048_keypair) -> None:
    store = DNSZoneStore()
    store.publish_dkim(
        domain="corp.example",
        selector="s2026",
        public_key_b64=rsa_2048_keypair.public_key().to_dkim_base64(),
    )

    raw = (
        "From: Security <sec@corp.example>\r\n"
        "To: User <user@partner.example>\r\n"
        "Subject: Quarterly Audit\r\n"
        "Date: Wed, 25 Nov 2026 10:00:00 +0000\r\n"
        "Message-ID: <audit-1@corp.example>\r\n"
        "\r\n"
        "Original unmodified body content.\r\n"
    )
    signed = sign_email(raw, domain="corp.example", selector="s2026", private_key=rsa_2048_keypair)
    results = verify_dkim_signatures(signed, store)
    assert len(results) == 1
    assert results[0].result == "pass"
    assert results[0].body_hash_valid is True
    assert results[0].signature_valid is True

    # Body tampering -> bh= mismatch
    tampered_body = signed.replace("Original unmodified", "Tampered malicious")
    res_body = verify_dkim_signatures(tampered_body, store)
    assert res_body[0].result == "fail"
    assert res_body[0].body_hash_valid is False

    # Header tampering -> RSA signature mismatch
    tampered_subj = signed.replace("Quarterly Audit", "Urgent Wire Transfer")
    res_hdr = verify_dkim_signatures(tampered_subj, store)
    assert res_hdr[0].result == "fail"
    assert res_hdr[0].body_hash_valid is True
    assert res_hdr[0].signature_valid is False


def test_dmarc_alignment_and_monitoring_to_reject_lifecycle(rsa_2048_keypair) -> None:
    assert get_organizational_domain("mail.alerts.corp.example") == "corp.example"
    assert domains_align("mail.corp.example", "corp.example", mode="r") is True
    assert domains_align("mail.corp.example", "corp.example", mode="s") is False

    store = DNSZoneStore()
    store.publish_spf("corp.example", "v=spf1 ip4:198.51.100.10 -all")
    store.publish_spf("thirdparty.example", "v=spf1 ip4:192.0.2.50 -all")
    store.publish_dkim("corp.example", "sel1", rsa_2048_keypair.public_key().to_dkim_base64())
    store.publish_dmarc("corp.example", policy="none", adkim="r", aspf="r", rua="mailto:dmarc@corp.example")

    lifecycle = DMARCLifecycleManager(domain="corp.example", dns_store=store, rua="mailto:dmarc@corp.example")

    # Should block premature promotion when no aligned message has been observed
    with pytest.raises(RuntimeError):
        lifecycle.transition_policy("reject")

    # Simulate an unaligned email during monitoring (p=none -> disposition=accept)
    spf_unaligned = evaluate_spf("192.0.2.50", "bounce@thirdparty.example", store)
    dmarc_mon = evaluate_dmarc("CEO <ceo@corp.example>", spf_unaligned, [], store)
    assert dmarc_mon.result == "fail"
    assert dmarc_mon.disposition == "accept"

    # Simulate aligned legitimate message in monitoring
    spf_ok = evaluate_spf("198.51.100.10", "sec@corp.example", store)
    dmarc_ok = evaluate_dmarc("Security <sec@corp.example>", spf_ok, [], store)
    assert dmarc_ok.result == "pass"
    assert dmarc_ok.spf_aligned is True
    lifecycle.record_observation("198.51.100.10", spf_ok, [], dmarc_ok)

    # Validate XML aggregate report
    xml_str = lifecycle.generate_aggregate_xml()
    root = ET.fromstring(xml_str)
    assert root.findtext("./policy_published/domain") == "corp.example"
    assert root.findtext("./record/row/policy_evaluated/spf") == "pass"

    # Promote to reject
    promoted = lifecycle.transition_policy("reject", adkim="s", aspf="s")
    assert "p=reject" in promoted["dmarc_record"]

    # Now unaligned spoofing is rejected
    dmarc_enforced = evaluate_dmarc("CEO <ceo@corp.example>", spf_unaligned, [], store)
    assert dmarc_enforced.result == "fail"
    assert dmarc_enforced.disposition == "reject"


def test_header_analyzer_detects_spoofing_and_parses_headers(tmp_path: Path, rsa_2048_keypair) -> None:
    store = DNSZoneStore()
    gw = SecureEmailGateway(config=GatewayConfig(), dns_store=store, keys_dir=tmp_path / "keys")
    gw.provision_domain(initial_dmarc_policy="reject", bind_output_path=None)

    signed = gw.compose_and_sign(
        sender="alerts@securemail.example",
        recipient="user@partner.example",
        subject="Normal Update",
        body="All checks passed.",
    )
    verdict = gw.process_inbound(signed, client_ip="198.51.100.10", mail_from="alerts@securemail.example")
    analysis_ok = analyze_raw_email(verdict.stamped_email, dns_store=store)
    assert analysis_ok.security_verdict == "TRUSTED"
    assert analysis_ok.risk_score == 0
    assert analysis_ok.spf_evaluation.result == "pass"
    assert analysis_ok.dkim_evaluations[0].result == "pass"
    assert analysis_ok.dmarc_evaluation.result == "pass"
    assert len(analysis_ok.upstream_auth_results) == 1

    # Phishing header-only snippet with display-name spoofing and Reply-To mismatch
    phish_headers = (
        "Received: from rogue.evil.example (unknown [192.0.2.200])\r\n"
        "\tby mx-gw.securemail.example with ESMTP; Wed, 25 Nov 2026 12:00:00 +0000\r\n"
        "Return-Path: <bounce@evil.example>\r\n"
        'From: "ceo@securemail.example" <attacker@evil.example>\r\n'
        "Reply-To: harvest@dropzone.example\r\n"
        "Subject: Urgent Invoice\r\n"
    )
    analysis_phish = analyze_raw_email(phish_headers, dns_store=store)
    assert analysis_phish.security_verdict == "MALICIOUS_OR_SPOOFED"
    assert analysis_phish.risk_score >= 55
    assert any("Display-name spoofing" in a for a in analysis_phish.anomalies)
    assert any("Reply-To" in a for a in analysis_phish.anomalies)


def test_cli_demo_and_web_api_endpoints() -> None:
    # Run full demo to ensure DNS zone, keys, samples, and reports are generated cleanly
    report = run_controlled_demo(regenerate_keys=False)
    assert report["monitoring_phase"]["summary"]["pass_rate"] == 1.0
    scenarios = {s["scenario"]: s for s in report["enforcement_scenarios"]}
    assert scenarios["Legitimate Signed & Aligned"]["gateway_disposition"] == "accept"
    assert scenarios["Spoofed Unauthorized IP"]["spf_result"] == "fail"
    assert scenarios["Spoofed Unauthorized IP"]["gateway_disposition"] == "reject"
    assert scenarios["Tampered Message Body (Broken DKIM)"]["spf_result"] == "fail"
    assert scenarios["Tampered Message Body (Broken DKIM)"]["dkim_result"] == "fail"
    assert scenarios["Unaligned Phishing Relay"]["gateway_disposition"] == "reject"

    # CLI analyze exit code & disk-saved .eml round-trip check
    assert cli_main(["analyze", "--input", str(_PKG_ROOT / "samples" / "01_legitimate_aligned.eml")]) == 0
    saved_legit = (_PKG_ROOT / "samples" / "01_legitimate_aligned.eml").read_bytes().decode("utf-8")
    assert analyze_raw_email(saved_legit, dns_store=DNSZoneStore(_PKG_ROOT / "config" / "dns_zones.json")).security_verdict == "TRUSTED"

    # FastAPI endpoints verification
    client = TestClient(app)
    assert client.get("/").status_code == 200
    assert client.get("/api/health").json()["status"] == "healthy"
    assert "v=spf1" in client.get("/api/dns").json()["bind_zone"]

    sign_resp = client.post(
        "/api/sign",
        json={"sender": "ops@securemail.example", "recipient": "bob@partner.example", "subject": "Test", "body": "Hello"},
    )
    assert sign_resp.status_code == 200
    signed_eml = sign_resp.json()["signed_email"]
    assert "DKIM-Signature:" in signed_eml

    analyze_resp = client.post(
        "/api/analyze",
        json={"raw_email": signed_eml, "client_ip": "198.51.100.10", "mail_from": "ops@securemail.example"},
    )
    assert analyze_resp.status_code == 200
    payload = analyze_resp.json()
    assert payload["security_verdict"] == "TRUSTED"
    assert payload["dmarc_evaluation"]["result"] == "pass"
