"""
ECDAT Scanner Adapters.

Concrete adapter implementations for discovery engines.
"""

from .cryptoscan import CryptoScanAdapter
from .syft import SyftAdapter

__all__ = [
    "CryptoScanAdapter",
    "SyftAdapter",
]
