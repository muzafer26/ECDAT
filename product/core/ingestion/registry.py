"""
ECDAT Adapter Registry.

Provides explicit, auditable in-memory registration and lookup of scanner adapters.
Zero dynamic filesystem execution or untrusted plugin discovery.
"""

from typing import Dict, List, Optional
from .adapter import ScannerAdapter


class AdapterRegistry:
    """Explicit in-memory registry of configured ScannerAdapter instances."""

    def __init__(self) -> None:
        self._adapters: Dict[str, ScannerAdapter] = {}

    def register(self, adapter: ScannerAdapter) -> None:
        """Register an adapter instance by its unique adapter_id."""
        if not isinstance(adapter, ScannerAdapter):
            raise TypeError(f"Expected ScannerAdapter instance, got {type(adapter)}")
        aid = adapter.adapter_id
        if not aid or not isinstance(aid, str):
            raise ValueError("Adapter must have a non-empty string adapter_id")
        if aid in self._adapters:
            raise ValueError(f"Adapter with ID '{aid}' is already registered")
        self._adapters[aid] = adapter

    def get(self, adapter_id: str) -> Optional[ScannerAdapter]:
        """Retrieve an adapter by ID, or None if not registered."""
        return self._adapters.get(adapter_id)

    def has(self, adapter_id: str) -> bool:
        """Check whether an adapter is registered."""
        return adapter_id in self._adapters

    def list_adapters(self) -> List[str]:
        """List all registered adapter IDs in deterministic order."""
        return sorted(self._adapters.keys())

    def clear(self) -> None:
        """Clear all registered adapters (useful for test isolation)."""
        self._adapters.clear()
