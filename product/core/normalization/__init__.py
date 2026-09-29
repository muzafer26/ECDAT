"""
ECDAT Core Normalization Package.
Provides normalization engine, taxonomy resolver, and conservative asset correlator.
"""

from .taxonomy import resolve_algorithm_family, infer_role_from_api, extract_parameters
from .normalizer import NormalizationEngine
from .correlation import AssetCorrelationEngine

__all__ = [
    "resolve_algorithm_family",
    "infer_role_from_api",
    "extract_parameters",
    "NormalizationEngine",
    "AssetCorrelationEngine",
]
