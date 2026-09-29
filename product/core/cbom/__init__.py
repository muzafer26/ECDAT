"""
ECDAT CBOM Package.

Provides CycloneDX 1.7 Cryptographic Bill of Materials projection,
deterministic serialization, and two-tier validation under strict
non-inference and zero silent semantic loss invariants.
"""

from .constants import (
    ALGORITHM_FAMILIES,
    ASSET_TYPES,
    CRYPTO_FUNCTIONS,
    CYCLONEDX_BOM_FORMAT,
    CYCLONEDX_SPEC_VERSION,
    ECDAT_PROPERTY_PREFIX,
    MODES,
    PADDINGS,
    PRIMITIVES,
)
from .projection import CBOMProjector
from .serializer import CBOMSerializer
from .validator import CBOMValidator, ValidationResult

__all__ = [
    "CYCLONEDX_SPEC_VERSION",
    "CYCLONEDX_BOM_FORMAT",
    "ECDAT_PROPERTY_PREFIX",
    "ALGORITHM_FAMILIES",
    "PRIMITIVES",
    "CRYPTO_FUNCTIONS",
    "MODES",
    "PADDINGS",
    "ASSET_TYPES",
    "CBOMProjector",
    "CBOMSerializer",
    "CBOMValidator",
    "ValidationResult",
]
