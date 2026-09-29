"""
ECDAT Cryptographic Taxonomy and Algorithm Mapping Rules.

Provides standard JCA/JCE and OpenSSL token mappings, role classifications,
and parameter extraction patterns.
"""

import re
from typing import Optional, Tuple
from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.role import CryptographicRole
from product.core.domain.parameters import AlgorithmParameters


# Standard algorithm family lookup by token
_FAMILY_MAP = {
    "RSA": AlgorithmFamily.RSA,
    "AES": AlgorithmFamily.AES,
    "EC": AlgorithmFamily.EC,
    "ECC": AlgorithmFamily.EC,
    "ECDSA": AlgorithmFamily.EC,
    "ECDH": AlgorithmFamily.EC,
    "ED25519": AlgorithmFamily.EDWARDS,
    "ED448": AlgorithmFamily.EDWARDS,
    "DH": AlgorithmFamily.DH,
    "DIFFIEHELLMAN": AlgorithmFamily.DH,
    "DES": AlgorithmFamily.DES,
    "3DES": AlgorithmFamily.DES,
    "DESEDE": AlgorithmFamily.DES,
    "SHA1": AlgorithmFamily.SHA1,
    "SHA-1": AlgorithmFamily.SHA1,
    "SHA256": AlgorithmFamily.SHA2,
    "SHA-256": AlgorithmFamily.SHA2,
    "SHA384": AlgorithmFamily.SHA2,
    "SHA-384": AlgorithmFamily.SHA2,
    "SHA512": AlgorithmFamily.SHA2,
    "SHA-512": AlgorithmFamily.SHA2,
}

# Explicit role inference by API invocation pattern
_API_ROLE_MAP = [
    (re.compile(r"Signature\.getInstance", re.IGNORECASE), CryptographicRole.DIGITAL_SIGNATURE),
    (re.compile(r"KeyAgreement\.getInstance", re.IGNORECASE), CryptographicRole.KEY_AGREEMENT),
    (re.compile(r"KeyPairGenerator\.getInstance", re.IGNORECASE), CryptographicRole.KEY_GENERATION),
    (re.compile(r"KeyGenerator\.getInstance", re.IGNORECASE), CryptographicRole.KEY_GENERATION),
    (re.compile(r"Cipher\.getInstance", re.IGNORECASE), CryptographicRole.ENCRYPTION_DECRYPTION),
    (re.compile(r"MessageDigest\.getInstance", re.IGNORECASE), CryptographicRole.MESSAGE_DIGEST),
    (re.compile(r"hashlib\.(?:sha1|sha256|sha512|md5)", re.IGNORECASE), CryptographicRole.MESSAGE_DIGEST),
    (re.compile(r"Mac\.getInstance", re.IGNORECASE), CryptographicRole.MAC),
]

# Curve name patterns
_CURVE_PATTERNS = [
    re.compile(r"(secp256r1|prime256v1|P-256)", re.IGNORECASE),
    re.compile(r"(secp384r1|P-384)", re.IGNORECASE),
    re.compile(r"(secp521r1|P-521)", re.IGNORECASE),
    re.compile(r"(secp256k1)", re.IGNORECASE),
    re.compile(r"(curve25519|ed25519)", re.IGNORECASE),
]

# Cipher mode patterns
_MODE_PATTERNS = [
    re.compile(r"/(GCM|CBC|CTR|ECB|CFB|OFB)/", re.IGNORECASE),
    re.compile(r"AES\.MODE_(GCM|CBC|CTR|ECB|CFB|OFB)", re.IGNORECASE),
    re.compile(r"\bMODE_(GCM|CBC|CTR|ECB)\b", re.IGNORECASE),
]

# Padding patterns
_PADDING_PATTERNS = [
    re.compile(r"/(PKCS1Padding|PKCS5Padding|PKCS7Padding|NoPadding|OAEPPadding)", re.IGNORECASE),
]


def resolve_algorithm_family(token: str) -> AlgorithmFamily:
    """Resolves an algorithm family from a token or string."""
    cleaned = token.strip().upper()
    return _FAMILY_MAP.get(cleaned, AlgorithmFamily.UNKNOWN)


def infer_role_from_api(code_text: str) -> CryptographicRole:
    """Infers operational cryptographic role from API invocation syntax."""
    if not code_text:
        return CryptographicRole.UNKNOWN
    for pattern, role in _API_ROLE_MAP:
        if pattern.search(code_text):
            return role
    return CryptographicRole.UNKNOWN


def extract_parameters(code_text: str, algorithm_name: str) -> AlgorithmParameters:
    """
    Extracts parameter attributes (key sizes, curve, mode, padding) from code evidence.
    Enforces parameter invariants (e.g. SHA-1 160-bit digest is not key size).
    """
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    curve: Optional[str] = None
    digest: Optional[str] = None
    effective_key: Optional[int] = None

    if not code_text:
        return AlgorithmParameters()

    # Extract curve name
    for pattern in _CURVE_PATTERNS:
        match = pattern.search(code_text)
        if match:
            curve = match.group(1).lower()
            if curve in ("p-256", "prime256v1"):
                curve = "secp256r1"
            break

    # Extract cipher mode
    for pattern in _MODE_PATTERNS:
        match = pattern.search(code_text)
        if match:
            mode = match.group(1).upper()
            break

    # Extract padding
    for pattern in _PADDING_PATTERNS:
        match = pattern.search(code_text)
        if match:
            padding = match.group(1)
            break

    # Extract key size where supported
    # RSA key size: e.g. initialize(2048) or KeyPairGenerator.initialize(2048)
    rsa_match = re.search(r"initialize\s*\(\s*(1024|2048|3072|4096)\b", code_text)
    if rsa_match:
        key_size = int(rsa_match.group(1))

    # AES key size: e.g. init(256) or 256-bit key byte array (32 bytes)
    aes_match = re.search(r"(?:init|KeyGenerator.*?init)\s*\(\s*(128|192|256)\b", code_text)
    if aes_match:
        key_size = int(aes_match.group(1))
    elif re.search(r"byte\[\]\s*key\s*=\s*new\s*byte\[32\]|os\.urandom\(32\)", code_text):
        key_size = 256
    elif re.search(r"byte\[\]\s*key\s*=\s*new\s*byte\[16\]|os\.urandom\(16\)", code_text):
        key_size = 128

    # DES effective strength vs encoded key size
    if "DES" in algorithm_name.upper():
        effective_key = 56
        if key_size is None:
            key_size = 64  # standard 64-bit encoded DES key with 8 parity bits

    # Extract digest algorithm for signatures or MACs
    sig_digest_match = re.search(r"(SHA256|SHA384|SHA512|SHA1)with", code_text, re.IGNORECASE)
    if sig_digest_match:
        d = sig_digest_match.group(1).upper()
        digest = f"{d[:3]}-{d[3:]}" if not d.startswith("SHA-") else d

    return AlgorithmParameters(
        key_size_bits=key_size,
        cipher_mode=mode,
        padding_scheme=padding,
        curve_name=curve,
        digest_algorithm=digest,
        effective_key_bits=effective_key,
    )
