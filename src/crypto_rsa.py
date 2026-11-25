"""Pure-Python RFC 8017 RSA-2048 cryptography for DKIM signing and verification.

Implements:
- Cryptographically secure RSA key-pair generation via `secrets` and Miller-Rabin
- ASN.1 DER serialization/parsing for PKCS#1 RSAPrivateKey and X.509 SubjectPublicKeyInfo
- PEM armor encoding/decoding and RFC 6376 DKIM `p=` Base64 public-key export
- RSASSA-PKCS1-v1_5 with SHA-256 signing and signature verification
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import secrets
from typing import Tuple


# RFC 8017 Section 9.2 DigestInfo prefix for SHA-256
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
# OID 1.2.840.113549.1.1.1 (rsaEncryption) + NULL parameter
_RSA_ALGORITHM_IDENTIFIER = bytes.fromhex("300d06092a864886f70d0101010500")

_SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
)


@dataclass(frozen=True)
class RSAPublicKey:
    """RSA public key components."""

    n: int
    e: int

    @property
    def key_size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def key_size_bits(self) -> int:
        return self.n.bit_length()

    def to_spki_der(self) -> bytes:
        """Encode as X.509 SubjectPublicKeyInfo DER bytes."""
        rsa_pub_seq = _der_sequence(
            _der_integer(self.n) + _der_integer(self.e)
        )
        bit_string = _der_bit_string(rsa_pub_seq)
        return _der_sequence(_RSA_ALGORITHM_IDENTIFIER + bit_string)

    def to_dkim_base64(self) -> str:
        """Return single-line Base64 SPKI string for DKIM DNS `p=` tag."""
        return base64.b64encode(self.to_spki_der()).decode("ascii")

    def to_pem(self) -> str:
        """Encode as PEM-armored PUBLIC KEY."""
        return _armor_pem("PUBLIC KEY", self.to_spki_der())


@dataclass(frozen=True)
class RSAPrivateKey:
    """RSA private key components (PKCS#1)."""

    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int

    @property
    def key_size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def key_size_bits(self) -> int:
        return self.n.bit_length()

    def public_key(self) -> RSAPublicKey:
        """Derive the corresponding RSAPublicKey."""
        return RSAPublicKey(n=self.n, e=self.e)

    def to_pkcs1_der(self) -> bytes:
        """Encode as PKCS#1 RSAPrivateKey DER bytes."""
        fields = [
            _der_integer(0),
            _der_integer(self.n),
            _der_integer(self.e),
            _der_integer(self.d),
            _der_integer(self.p),
            _der_integer(self.q),
            _der_integer(self.dp),
            _der_integer(self.dq),
            _der_integer(self.qinv),
        ]
        return _der_sequence(b"".join(fields))

    def to_pem(self) -> str:
        """Encode as PEM-armored RSA PRIVATE KEY."""
        return _armor_pem("RSA PRIVATE KEY", self.to_pkcs1_der())


# ---------------------------------------------------------------------------
# ASN.1 DER helpers
# ---------------------------------------------------------------------------


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("DER integer helper expects non-negative integers.")
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_sequence(content: bytes) -> bytes:
    return _der_tlv(0x30, content)


def _der_bit_string(content: bytes) -> bytes:
    return _der_tlv(0x03, b"\x00" + content)


def _read_der_tlv(data: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of DER data.")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("Truncated DER length.")
    first_len = data[offset]
    offset += 1
    if first_len < 0x80:
        length = first_len
    else:
        num_bytes = first_len & 0x7F
        if num_bytes == 0 or offset + num_bytes > len(data):
            raise ValueError("Invalid DER length encoding.")
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        offset += num_bytes
    end = offset + length
    if end > len(data):
        raise ValueError("DER element exceeds buffer length.")
    return tag, data[offset:end], end


def _parse_der_sequence(data: bytes) -> list[Tuple[int, bytes]]:
    tag, content, end = _read_der_tlv(data, 0)
    if tag != 0x30 or end != len(data):
        raise ValueError("Expected top-level DER SEQUENCE.")
    items: list[Tuple[int, bytes]] = []
    pos = 0
    while pos < len(content):
        item_tag, item_val, pos = _read_der_tlv(content, pos)
        items.append((item_tag, item_val))
    return items


def _armor_pem(label: str, der_bytes: bytes) -> str:
    b64 = base64.encodebytes(der_bytes).decode("ascii").strip()
    return f"-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n"


def _unarmor_pem(pem_text: str, expected_label: str) -> bytes:
    lines = [
        line.strip()
        for line in pem_text.strip().splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    if f"BEGIN {expected_label}" not in pem_text:
        raise ValueError(f"Expected PEM label '{expected_label}'.")
    return base64.b64decode("".join(lines))


# ---------------------------------------------------------------------------
# Key generation & serialization
# ---------------------------------------------------------------------------


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for prime in _SMALL_PRIMES:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    # Write n - 1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        # Ensure exact bit-length and oddness (top two bits set so p*q has exact bit width)
        candidate |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> RSAPrivateKey:
    """Generate a fresh RSA key pair of `bits` modulus size (default 2048)."""
    if bits < 1024 or bits % 2 != 0:
        raise ValueError("RSA key size must be an even integer >= 1024.")

    half_bits = bits // 2
    while True:
        p = _generate_prime(half_bits)
        q = _generate_prime(half_bits)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        d = pow(e, -1, phi)
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = pow(q, -1, p)
        return RSAPrivateKey(n=n, e=e, d=d, p=p, q=q, dp=dp, dq=dq, qinv=qinv)


def parse_private_key_pem(pem_text: str) -> RSAPrivateKey:
    """Decode a PKCS#1 PEM private key."""
    der = _unarmor_pem(pem_text, "RSA PRIVATE KEY")
    items = _parse_der_sequence(der)
    if len(items) < 9 or any(tag != 0x02 for tag, _ in items[:9]):
        raise ValueError("Invalid PKCS#1 RSAPrivateKey ASN.1 structure.")
    vals = [int.from_bytes(val, "big") for _, val in items[:9]]
    return RSAPrivateKey(
        n=vals[1],
        e=vals[2],
        d=vals[3],
        p=vals[4],
        q=vals[5],
        dp=vals[6],
        dq=vals[7],
        qinv=vals[8],
    )


def parse_public_key_spki_der(der_bytes: bytes) -> RSAPublicKey:
    """Decode an X.509 SubjectPublicKeyInfo DER public key (used in DKIM p=)."""
    top_items = _parse_der_sequence(der_bytes)
    if len(top_items) != 2 or top_items[1][0] != 0x03:
        raise ValueError("Invalid SubjectPublicKeyInfo ASN.1 structure.")
    bit_payload = top_items[1][1]
    if not bit_payload or bit_payload[0] != 0:
        raise ValueError("Unsupported BIT STRING unused-bits padding.")
    rsa_items = _parse_der_sequence(bit_payload[1:])
    if len(rsa_items) != 2 or rsa_items[0][0] != 0x02 or rsa_items[1][0] != 0x02:
        raise ValueError("Invalid inner RSAPublicKey ASN.1 sequence.")
    n = int.from_bytes(rsa_items[0][1], "big")
    e = int.from_bytes(rsa_items[1][1], "big")
    return RSAPublicKey(n=n, e=e)


def parse_public_key_dkim_b64(b64_text: str) -> RSAPublicKey:
    """Parse a DKIM DNS `p=` Base64 public key (SPKI DER or raw PKCS#1)."""
    compact = "".join(b64_text.split())
    der = base64.b64decode(compact)
    try:
        return parse_public_key_spki_der(der)
    except ValueError:
        # Fallback: some legacy DKIM records store raw PKCS#1 RSAPublicKey DER
        rsa_items = _parse_der_sequence(der)
        if len(rsa_items) != 2:
            raise
        n = int.from_bytes(rsa_items[0][1], "big")
        e = int.from_bytes(rsa_items[1][1], "big")
        return RSAPublicKey(n=n, e=e)


def parse_public_key_pem(pem_text: str) -> RSAPublicKey:
    """Decode a PEM PUBLIC KEY."""
    der = _unarmor_pem(pem_text, "PUBLIC KEY")
    return parse_public_key_spki_der(der)


def save_keypair(
    private_key: RSAPrivateKey,
    private_path: Path,
    public_path: Path,
) -> None:
    """Persist private and public keys to PEM files."""
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_text(private_key.to_pem(), encoding="utf-8")
    public_path.write_text(private_key.public_key().to_pem(), encoding="utf-8")


# ---------------------------------------------------------------------------
# RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 Section 8.2)
# ---------------------------------------------------------------------------


def _emsa_pkcs1_v1_5_encode_sha256(message: bytes, em_len: int) -> bytes:
    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGEST_INFO_PREFIX + digest
    if em_len < len(t) + 11:
        raise ValueError("RSA modulus too short for PKCS#1 v1.5 SHA-256 signature.")
    ps_len = em_len - len(t) - 3
    return b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + t


def sign_rsa_sha256(message: bytes, private_key: RSAPrivateKey) -> bytes:
    """Sign `message` using RSASSA-PKCS1-v1_5 with SHA-256."""
    k = private_key.key_size_bytes
    em = _emsa_pkcs1_v1_5_encode_sha256(message, k)
    m = int.from_bytes(em, "big")
    # CRT acceleration for fast signing
    m1 = pow(m, private_key.dp, private_key.p)
    m2 = pow(m, private_key.dq, private_key.q)
    h = (private_key.qinv * (m1 - m2)) % private_key.p
    s = m2 + h * private_key.q
    return s.to_bytes(k, "big")


def verify_rsa_sha256(
    message: bytes, signature: bytes, public_key: RSAPublicKey
) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 SHA-256 signature."""
    k = public_key.key_size_bytes
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= public_key.n:
        return False
    m = pow(s, public_key.e, public_key.n)
    em = m.to_bytes(k, "big")
    try:
        expected = _emsa_pkcs1_v1_5_encode_sha256(message, k)
    except ValueError:
        return False
    return secrets.compare_digest(em, expected)
