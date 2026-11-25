"""Configuration defaults and path constants for the Secure Email Authentication Gateway."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
KEYS_DIR = BASE_DIR / "keys"
REPORTS_DIR = BASE_DIR / "reports"
SAMPLES_DIR = BASE_DIR / "samples"
DNS_ZONE_PATH = CONFIG_DIR / "dns_zones.json"
BIND_ZONE_PATH = CONFIG_DIR / "securemail.example.zone"


@dataclass(frozen=True)
class GatewayConfig:
    """Central configuration for the controlled email authentication domain."""

    domain: str = "securemail.example"
    dkim_selector: str = "selector1"
    key_bits: int = 2048
    authorized_ips: List[str] = field(
        default_factory=lambda: ["198.51.100.10", "203.0.113.0/24"]
    )
    authorized_ipv6: List[str] = field(default_factory=lambda: ["2001:db8:cafe::/48"])
    rua_email: str = "mailto:dmarc-reports@securemail.example"
    ruf_email: str = "mailto:dmarc-forensic@securemail.example"
    min_monitoring_pass_rate: float = 0.95
    min_monitoring_samples: int = 3
