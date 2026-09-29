"""
ECDAT Algorithm Parameters Domain Model.

Captures typed parameter attributes (key sizes, curve, mode, padding).
Enforces parameter integrity (e.g. digest output length is not a key size).
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class AlgorithmParameters:
    """
    Cryptographic configuration parameters.
    
    Invariants:
    - key_size_bits must be an integer if present.
    - digest output length is never stored in key_size_bits.
    - effective_key_bits distinguishes effective security from encoded key size (e.g. DES 56 vs 64).
    """
    key_size_bits: Optional[int] = None
    cipher_mode: Optional[str] = None
    padding_scheme: Optional[str] = None
    curve_name: Optional[str] = None
    digest_algorithm: Optional[str] = None
    effective_key_bits: Optional[int] = None

    def __post_init__(self) -> None:
        if self.key_size_bits is not None and not isinstance(self.key_size_bits, int):
            try:
                object.__setattr__(self, "key_size_bits", int(self.key_size_bits))
            except (ValueError, TypeError):
                object.__setattr__(self, "key_size_bits", None)

        if self.effective_key_bits is not None and not isinstance(self.effective_key_bits, int):
            try:
                object.__setattr__(self, "effective_key_bits", int(self.effective_key_bits))
            except (ValueError, TypeError):
                object.__setattr__(self, "effective_key_bits", None)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_size_bits": self.key_size_bits,
            "cipher_mode": self.cipher_mode,
            "padding_scheme": self.padding_scheme,
            "curve_name": self.curve_name,
            "digest_algorithm": self.digest_algorithm,
            "effective_key_bits": self.effective_key_bits,
        }

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "AlgorithmParameters":
        if not data:
            return cls()
        return cls(
            key_size_bits=data.get("key_size_bits"),
            cipher_mode=data.get("cipher_mode"),
            padding_scheme=data.get("padding_scheme"),
            curve_name=data.get("curve_name"),
            digest_algorithm=data.get("digest_algorithm"),
            effective_key_bits=data.get("effective_key_bits"),
        )
