"""
ECDAT Algorithm Identity and Taxonomy Model.

Strictly decouples algorithm family from specific algorithm.
Never collapses distinct primitives (ECDSA, ECDH, Ed25519) into a single "ECC" token.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class AlgorithmFamily(str, Enum):
    """Broad mathematical or algorithmic family."""
    RSA = "RSA"
    AES = "AES"
    EC = "EC"
    EDWARDS = "EDWARDS"
    DH = "DH"
    DES = "DES"
    SHA1 = "SHA1"
    SHA2 = "SHA2"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "AlgorithmFamily":
        if not value:
            return cls.UNKNOWN
        val = value.strip().upper()
        # Aliases
        aliases = {
            "ECC": cls.EC,
            "ELLIPTIC_CURVE": cls.EC,
            "ED25519": cls.EDWARDS,
            "ED448": cls.EDWARDS,
            "DIFFIE_HELLMAN": cls.DH,
            "SHA-1": cls.SHA1,
            "SHA-256": cls.SHA2,
            "SHA-384": cls.SHA2,
            "SHA-512": cls.SHA2,
            "3DES": cls.DES,
            "TRIPLEDES": cls.DES,
        }
        if val in aliases:
            return aliases[val]
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNKNOWN


@dataclass(frozen=True)
class AlgorithmIdentity:
    """
    Precise canonical algorithm classification.
    
    Invariants:
    - family, algorithm, and variant are tracked independently.
    - Specificity requires explicit evidence: if only generic ECC is evidenced,
      family=EC and algorithm='UNKNOWN'.
    - Never collapses ECDSA/ECDH/Ed25519 into generic ECC.
    """
    family: AlgorithmFamily
    algorithm: str
    variant: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.family, AlgorithmFamily):
            object.__setattr__(self, "family", AlgorithmFamily.from_str(str(self.family)))
        if not self.algorithm:
            object.__setattr__(self, "algorithm", "UNKNOWN")
        else:
            object.__setattr__(self, "algorithm", self.algorithm.strip())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family.value,
            "algorithm": self.algorithm,
            "variant": self.variant,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlgorithmIdentity":
        return cls(
            family=AlgorithmFamily.from_str(data.get("family")),
            algorithm=data.get("algorithm", "UNKNOWN"),
            variant=data.get("variant"),
        )
