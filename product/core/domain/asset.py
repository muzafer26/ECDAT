"""
ECDAT Canonical Cryptographic Asset Domain Model.

Represents an underlying cryptographic entity inferred from one or more findings.
"""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Sequence
import uuid

from product.core.evidence.evidence import EvidenceLocation, SourceLocation
from .finding import FrozenIdTuple
from .algorithm import AlgorithmIdentity
from .role import CryptographicRole
from .parameters import AlgorithmParameters
from .confidence import ConfidenceLevel


class AssetType(str, Enum):
    """Categorical classification of the cryptographic asset."""
    ALGORITHM = "algorithm"
    PROTOCOL = "protocol"
    CERTIFICATE = "certificate"
    CRYPTO_KEY = "crypto_key"
    LIBRARY_DEPENDENCY = "library_dependency"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "AssetType":
        if not value:
            return cls.UNKNOWN
        val = value.strip().lower()
        for member in cls:
            if member.value == val or member.name.lower() == val:
                return member
        return cls.UNKNOWN


@dataclass(frozen=True)
class CanonicalAssetKey:
    """
    Authoritative, deterministic semantic identity key for a Cryptographic Asset.
    Composed strictly of identity-bearing domain attributes.
    Zero dependency on finding IDs, evidence IDs, scanner names, or timestamps.
    """
    asset_type: str
    location_anchor: str
    algorithm_family: str
    algorithm_name: str
    algorithm_variant: str
    role: str
    parameter_signature: str

    def canonical_string(self) -> str:
        return (
            f"asset_type={self.asset_type}|"
            f"loc={self.location_anchor}|"
            f"family={self.algorithm_family}|"
            f"algo={self.algorithm_name}|"
            f"variant={self.algorithm_variant}|"
            f"role={self.role}|"
            f"params={self.parameter_signature}"
        )

    def derive_asset_id(self) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"ecdat:asset:{self.canonical_string()}"))

    @classmethod
    def build(
        cls,
        asset_type: AssetType,
        location: EvidenceLocation,
        algorithm_identity: AlgorithmIdentity,
        role: CryptographicRole,
        parameters: AlgorithmParameters,
    ) -> "CanonicalAssetKey":
        loc_anchor = cls._build_location_anchor(location)
        param_sig = cls._build_parameter_signature(parameters)

        return cls(
            asset_type=asset_type.value,
            location_anchor=loc_anchor,
            algorithm_family=algorithm_identity.family.value,
            algorithm_name=algorithm_identity.algorithm,
            algorithm_variant=algorithm_identity.variant or "",
            role=role.value,
            parameter_signature=param_sig,
        )

    @classmethod
    def _build_location_anchor(cls, loc: EvidenceLocation) -> str:
        if loc.location_type.value == "source" or loc.file_path:
            anchor = f"file={loc.file_path or 'unknown'}:L{loc.line_start or 0}-{loc.line_end or 0}"
            if loc.column_start is not None and loc.column_end is not None:
                anchor += f":C{loc.column_start}-{loc.column_end}"
            elif loc.matched_text:
                # Canonical token fingerprint to disambiguate multi-statement lines when columns absent
                tok = re.sub(r"\s+", "", loc.matched_text.strip())[:40]
                if tok:
                    anchor += f":tok={tok}"
            return anchor
        elif loc.location_type.value == "dependency":
            return f"dep={loc.package_coordinate or 'unknown'}"
        elif loc.location_type.value == "network":
            return f"net={loc.endpoint or 'unknown'}:{loc.port or 0}"
        elif loc.location_type.value == "container":
            return f"container={loc.container_image or 'unknown'}:{loc.layer_digest or ''}"
        elif loc.location_type.value == "certificate":
            return f"cert={loc.certificate_id or 'unknown'}"
        elif loc.location_type.value == "binary":
            return f"bin={loc.binary_artifact or 'unknown'}"
        else:
            return f"other={loc.matched_text[:40]}"

    @classmethod
    def _build_parameter_signature(cls, params: AlgorithmParameters) -> str:
        parts = []
        if params.cipher_mode:
            parts.append(f"mode={params.cipher_mode.upper()}")
        if params.key_size_bits:
            parts.append(f"keysize={params.key_size_bits}")
        if params.curve_name:
            parts.append(f"curve={params.curve_name.lower()}")
        if params.digest_algorithm:
            parts.append(f"digest={params.digest_algorithm.upper()}")
        return ";".join(parts) if parts else "none"


@dataclass(frozen=True)
class CryptoAsset:
    """
    Canonical Cryptographic Asset entity.
    
    Invariants:
    - Immutable after creation (frozen=True).
    - Findings != Assets. Multiple findings may map to one asset.
    - Zero generic context metadata dumping fields.
    - Deterministic asset_id derived from CanonicalAssetKey (zero dependency on finding IDs).
    - correlation_basis explicitly documents the deterministic rule and evidence
      that correlated the findings into this single asset.
    """
    asset_id: str
    asset_type: AssetType
    algorithm_identity: AlgorithmIdentity
    role: CryptographicRole
    parameters: AlgorithmParameters
    finding_ids: Sequence[str]
    primary_location: EvidenceLocation
    confidence: ConfidenceLevel
    correlation_basis: str
    asset_key: Optional[CanonicalAssetKey] = None

    def __post_init__(self) -> None:
        if not self.finding_ids:
            raise ValueError("CryptoAsset must reference at least one finding_id")

        frozen_ids = FrozenIdTuple(self.finding_ids)
        object.__setattr__(self, "finding_ids", frozen_ids)

        if not isinstance(self.asset_type, AssetType):
            object.__setattr__(self, "asset_type", AssetType.from_str(str(self.asset_type)))
        if not isinstance(self.role, CryptographicRole):
            object.__setattr__(self, "role", CryptographicRole.from_str(str(self.role)))
        if not isinstance(self.confidence, ConfidenceLevel):
            object.__setattr__(self, "confidence", ConfidenceLevel.from_str(str(self.confidence)))
        if not self.correlation_basis:
            object.__setattr__(self, "correlation_basis", "single_source_observation")

        # Build canonical key if not present
        if not self.asset_key:
            key = CanonicalAssetKey.build(
                asset_type=self.asset_type,
                location=self.primary_location,
                algorithm_identity=self.algorithm_identity,
                role=self.role,
                parameters=self.parameters,
            )
            object.__setattr__(self, "asset_key", key)

        if not self.asset_id:
            object.__setattr__(self, "asset_id", self.asset_key.derive_asset_id())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type.value,
            "algorithm_identity": self.algorithm_identity.to_dict(),
            "role": self.role.value,
            "parameters": self.parameters.to_dict(),
            "finding_ids": list(self.finding_ids),
            "primary_location": self.primary_location.to_dict(),
            "confidence": self.confidence.value,
            "correlation_basis": self.correlation_basis,
            "canonical_key": self.asset_key.canonical_string() if self.asset_key else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CryptoAsset":
        return cls(
            asset_id=data.get("asset_id", ""),
            asset_type=AssetType.from_str(data.get("asset_type")),
            algorithm_identity=AlgorithmIdentity.from_dict(data["algorithm_identity"]),
            role=CryptographicRole.from_str(data.get("role")),
            parameters=AlgorithmParameters.from_dict(data.get("parameters")),
            finding_ids=tuple(data.get("finding_ids", [])),
            primary_location=EvidenceLocation.from_dict(data["primary_location"]),
            confidence=ConfidenceLevel.from_str(data.get("confidence")),
            correlation_basis=data.get("correlation_basis", "deserialized_record"),
        )
