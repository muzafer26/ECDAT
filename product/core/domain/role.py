"""
ECDAT Cryptographic Role Model.

Represents operational cryptographic functions ONLY.
Decoys and comments are NOT cryptographic operations and are represented via ObservationType.
"""

from enum import Enum
from typing import Optional


class CryptographicRole(str, Enum):
    """
    Operational cryptographic role enacted by a primitive.
    Strictly restricted to functional cryptographic operations.
    """
    ENCRYPTION_DECRYPTION = "encryption_decryption"
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_AGREEMENT = "key_agreement"
    KEY_GENERATION = "key_generation"
    MESSAGE_DIGEST = "message_digest"
    MAC = "mac"
    KEY_DERIVATION = "key_derivation"
    RANDOM_GENERATION = "random_generation"
    CERTIFICATE_OPERATIONS = "certificate_operations"
    PROTOCOL_HANDSHAKE = "protocol_handshake"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "CryptographicRole":
        if not value:
            return cls.UNKNOWN
        val = value.strip().lower()
        # Aliases mapping from existing benchmark terms
        aliases = {
            "key_establishment": cls.KEY_AGREEMENT,
            "signature": cls.DIGITAL_SIGNATURE,
            "digest": cls.MESSAGE_DIGEST,
            "hash": cls.MESSAGE_DIGEST,
            "encryption": cls.ENCRYPTION_DECRYPTION,
            "decryption": cls.ENCRYPTION_DECRYPTION,
        }
        if val in aliases:
            return aliases[val]
        for member in cls:
            if member.value == val or member.name.lower() == val:
                return member
        return cls.UNKNOWN
