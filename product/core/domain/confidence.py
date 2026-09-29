"""
ECDAT Confidence and Review Disposition Enums.

Strictly separates:
- Confidence: "How confident is ECDAT in this cryptographic interpretation?"
- Disposition: "What is the review or lifecycle classification of this observation?"
"""

from enum import Enum
from typing import Optional


class ConfidenceLevel(str, Enum):
    """
    ECDAT's analytical confidence in its derived cryptographic interpretation.
    Note: FALSE_POSITIVE_IF_DETECTED is strictly a test oracle concept, not a production confidence level.
    """
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    POSSIBLE = "POSSIBLE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "ConfidenceLevel":
        if not value:
            return cls.UNKNOWN
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNKNOWN


class DispositionStatus(str, Enum):
    """
    Review disposition and triage classification of an observation.
    """
    UNREVIEWED = "UNREVIEWED"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUPPRESSED = "SUPPRESSED"
    NEEDS_REVIEW = "NEEDS_REVIEW"

    @classmethod
    def from_str(cls, value: Optional[str]) -> "DispositionStatus":
        if not value:
            return cls.UNREVIEWED
        val = value.strip().upper()
        for member in cls:
            if member.value == val or member.name == val:
                return member
        return cls.UNREVIEWED
