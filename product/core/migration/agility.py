"""
ECDAT Cryptographic Agility Assessor — Phase 4A.

Assesses the architectural agility of a cryptographic asset based strictly on
observable static AST facts, code snippets, and call-site contexts.

Mandatory Invariant:
- Never invents pseudo-numeric agility scores ungrounded in evidence.
- Categorical evaluation only (HARDCODED, CONFIGURABLE, MODULAR_PROVIDER, UNEVALUATED).
- Distinguishes direct hardcoded API calls from configurable or indirect wrapper invocations.
"""

import re
from typing import List, Tuple

from product.core.domain.asset import AssetType, CryptoAsset
from product.core.evidence.evidence import LocationType
from .models import AgilityAssessment, AgilityLevel


# Patterns indicative of dynamic, configuration-driven, or environmental retrieval
CONFIGURABLE_PATTERNS = (
    r"System\.getenv",
    r"System\.getProperty",
    r"config\.",
    r"properties\.",
    r"getProperty\(",
    r"os\.environ",
    r"os\.getenv",
    r"settings\.",
    r"env\[",
)

# Patterns indicative of custom helper, wrapper, or provider abstraction
WRAPPER_INDICATORS = (
    "helper",
    "wrapper",
    "factory",
    "provider",
    "service",
    "adapter",
    "handler",
    "util",
)


def assess_cryptographic_agility(asset: CryptoAsset) -> AgilityAssessment:
    """
    Evaluates the agility posture of a CryptoAsset based strictly on observed source evidence.

    Returns:
        AgilityAssessment containing:
        - AgilityLevel (HARDCODED, CONFIGURABLE, MODULAR_PROVIDER, UNEVALUATED)
        - Tuple of evidenced factors
        - Tuple of limitations and unknowns
        - Protocol context description
    """
    loc = asset.primary_location
    evidenced: List[str] = []
    limitations: List[str] = []

    # 1. Non-source locations (e.g. dependency manifests, network endpoints)
    if loc.location_type != LocationType.SOURCE:
        limitations.append(
            f"Location type is '{loc.location_type.value}'; call-site source code is unobserved in static AST."
        )
        return AgilityAssessment(
            level=AgilityLevel.UNEVALUATED,
            evidenced_factors=tuple(evidenced),
            limitations_and_unknowns=tuple(limitations),
            protocol_context="non_source_dependency" if loc.location_type == LocationType.DEPENDENCY else "external",
        )

    # 2. Empty code snippet and matched text
    text = (loc.matched_text or "").strip()
    snippet = (loc.code_snippet or "").strip()
    combined_code = f"{text}\n{snippet}"

    if not text and not snippet:
        limitations.append("Static AST matched text and code snippet are empty; cannot inspect call-site agility.")
        return AgilityAssessment(
            level=AgilityLevel.UNEVALUATED,
            evidenced_factors=tuple(evidenced),
            limitations_and_unknowns=tuple(limitations),
            protocol_context="unobserved",
        )

    # 3. Check for dynamic / configurable retrieval patterns
    is_configurable = False
    for pat in CONFIGURABLE_PATTERNS:
        if re.search(pat, combined_code, re.IGNORECASE):
            is_configurable = True
            evidenced.append(f"Configurable retrieval pattern detected matching '{pat}' at call site.")
            break

    # 4. Check for wrapper / modular provider abstraction
    file_path_lower = (loc.file_path or "").lower()
    has_wrapper_structure = any(w in file_path_lower for w in WRAPPER_INDICATORS)
    if has_wrapper_structure:
        evidenced.append(f"Call site resides in abstraction/wrapper module: '{loc.file_path}'.")

    # 5. Check for hardcoded string literals (e.g. getInstance("RSA"), new SecretKeySpec(..., "AES"))
    has_hardcoded_literal = False
    if re.search(r'getInstance\s*\(\s*["\']', combined_code) or re.search(r'new\s+SecretKeySpec\s*\(.*["\']', combined_code):
        has_hardcoded_literal = True
        evidenced.append("Cryptographic algorithm or parameters are instantiated via hardcoded string literal.")

    # Determine final level
    if is_configurable:
        level = AgilityLevel.CONFIGURABLE
    elif has_wrapper_structure and not has_hardcoded_literal:
        level = AgilityLevel.MODULAR_PROVIDER
    elif has_hardcoded_literal:
        level = AgilityLevel.HARDCODED
        limitations.append("Hardcoded algorithm string requires code compilation and deployment to alter.")
    else:
        # Default when AST evidence is present but does not show clear config or wrapper
        level = AgilityLevel.HARDCODED
        evidenced.append("Direct cryptographic API invocation evidenced without dynamic configuration parameters.")

    protocol_context = "local_direct_api"
    if has_wrapper_structure:
        protocol_context = "modular_wrapper_facade"
    elif is_configurable:
        protocol_context = "dynamic_configuration"

    return AgilityAssessment(
        level=level,
        evidenced_factors=tuple(evidenced),
        limitations_and_unknowns=tuple(limitations),
        protocol_context=protocol_context,
    )
