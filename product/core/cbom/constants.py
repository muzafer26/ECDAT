"""
CycloneDX 1.7 CBOM Constants and Authoritative Schema Enumerations.

Defines all official enumerations, schema constraints, and property namespaces
governing CycloneDX 1.7 Cryptographic Bill of Materials generation.
"""

from typing import FrozenSet, Tuple

CYCLONEDX_SPEC_VERSION: str = "1.7"
CYCLONEDX_BOM_FORMAT: str = "CycloneDX"
ECDAT_PROPERTY_PREFIX: str = "ecdat:"

# Official 93 algorithm families from cryptography-defs.schema.json#/definitions/algorithmFamiliesEnum
ALGORITHM_FAMILIES_TUPLE: Tuple[str, ...] = (
    "3DES", "3GPP-XOR", "A5/1", "A5/2", "AES", "ARIA", "Argon2", "Ascon",
    "BLAKE2", "BLAKE3", "BLS", "Blowfish", "CAMELLIA", "CAST5", "CAST6",
    "CMAC", "CMEA", "CTR_DRBG", "ChaCha", "ChaCha20", "DES", "DSA",
    "ECDH", "ECDSA", "ECIES", "EdDSA", "ElGamal", "FFDH", "Fortuna",
    "GOST", "HC", "HKDF", "HMAC", "HMAC_DRBG", "HPKE", "Hash_DRBG",
    "IDEA", "IKE-PRF", "J-PAKE", "LMS", "MD2", "MD4", "MD5", "MILENAGE",
    "ML-DSA", "ML-KEM", "MQV", "OPAQUE", "PBES1", "PBES2", "PBKDF1",
    "PBKDF2", "PBMAC1", "Poly1305", "RABBIT", "RC2", "RC4", "RC5",
    "RC6", "RIPEMD", "RSAES-OAEP", "RSAES-PKCS1", "RSASSA-PKCS1",
    "RSASSA-PSS", "SEED", "SHA-1", "SHA-2", "SHA-3", "SLH-DSA", "SM2",
    "SM3", "SM4", "SM9", "SNOW3G", "SP800-108", "SPAKE2", "SPAKE2PLUS",
    "SRP", "Salsa20", "Serpent", "SipHash", "Skipjack", "TUAK",
    "Twofish", "UMAC", "Whirlpool", "X3DH", "XMSS", "Yarrow", "ZUC",
    "bcrypt", "scrypt", "yescrypt"
)
ALGORITHM_FAMILIES: FrozenSet[str] = frozenset(ALGORITHM_FAMILIES_TUPLE)

# Official primitive enum values from bom-1.7.schema.json#/definitions/algorithmProperties/properties/primitive
PRIMITIVES_TUPLE: Tuple[str, ...] = (
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
    "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "key-wrap",
    "other", "unknown"
)
PRIMITIVES: FrozenSet[str] = frozenset(PRIMITIVES_TUPLE)

# Official cryptoFunctions enum values
CRYPTO_FUNCTIONS_TUPLE: Tuple[str, ...] = (
    "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
    "sign", "verify", "encapsulate", "decapsulate", "other", "unknown"
)
CRYPTO_FUNCTIONS: FrozenSet[str] = frozenset(CRYPTO_FUNCTIONS_TUPLE)

# Official mode enum values
MODES_TUPLE: Tuple[str, ...] = (
    "cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"
)
MODES: FrozenSet[str] = frozenset(MODES_TUPLE)

# Official padding enum values
PADDINGS_TUPLE: Tuple[str, ...] = (
    "pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"
)
PADDINGS: FrozenSet[str] = frozenset(PADDINGS_TUPLE)

# Official assetType enum values
ASSET_TYPES_TUPLE: Tuple[str, ...] = (
    "algorithm", "certificate", "protocol", "related-crypto-material"
)
ASSET_TYPES: FrozenSet[str] = frozenset(ASSET_TYPES_TUPLE)

# Official executionEnvironment enum values
EXECUTION_ENVIRONMENTS_TUPLE: Tuple[str, ...] = (
    "software-plain-ram", "software-encrypted-ram", "software-tee",
    "hardware", "other", "unknown"
)
EXECUTION_ENVIRONMENTS: FrozenSet[str] = frozenset(EXECUTION_ENVIRONMENTS_TUPLE)

# Official implementationPlatform enum values
IMPLEMENTATION_PLATFORMS_TUPLE: Tuple[str, ...] = (
    "generic", "x86_32", "x86_64", "armv7-a", "armv7-m", "armv8-a",
    "armv8-m", "armv9-a", "armv9-m", "s390x", "ppc64", "ppc64le",
    "other", "unknown"
)
IMPLEMENTATION_PLATFORMS: FrozenSet[str] = frozenset(IMPLEMENTATION_PLATFORMS_TUPLE)
