"""
ECDAT Observation Classification Model.

Captures the nature of the detected code element or finding.
Decoys and comments are observations, NOT cryptographic roles.
"""

from enum import Enum
from typing import Optional


class ObservationType(str, Enum):
    """
    Categorization of what was observed in source code, manifests, or configuration.
    """
    CRYPTOGRAPHIC_USAGE = "cryptographic_usage"      # Active cryptographic initialization or execution
    LIBRARY_DEPENDENCY = "library_dependency"        # Manifest/lockfile package declaration
    CONFIGURATION = "configuration"                  # Cryptographic parameter in config file or environment
    COMMENT_ONLY = "comment_only"                    # Keyword found exclusively inside comment or docstring
    NON_CRYPTOGRAPHIC_DECOY = "non_cryptographic_decoy"  # Decoy variable name, log text, or string literal
    AMBIGUOUS_CALL = "ambiguous_call"                # Unresolved dynamic or reflection-based cryptographic invocation

    @classmethod
    def from_str(cls, value: Optional[str]) -> "ObservationType":
        if not value:
            return cls.CRYPTOGRAPHIC_USAGE
        val = value.strip().lower()
        for member in cls:
            if member.value == val or member.name.lower() == val:
                return member
        return cls.CRYPTOGRAPHIC_USAGE
