"""
ECDAT Demo Adapter Registry & Boundary.

Provides the architectural discovery boundary, wrapping the real ECDAT
AdapterRegistry and honestly disclosing implementation readiness.
"""

from typing import Dict, List, Optional
from product.core.ingestion.adapters.cryptoscan import CryptoScanAdapter
from product.core.ingestion.adapters.syft import SyftAdapter
from product.core.ingestion.registry import AdapterRegistry
from demo.adapters.demo_source_adapter import DemoSourceAdapter
from .models import AdapterStatusInfo, CapabilityClassification


class DemoAdapterRegistry:
    """
    Exposes discovery adapter status and interfaces to the demo orchestration layer.
    Directly binds to product/core/ingestion/registry.py.
    """

    def __init__(self, core_registry: Optional[AdapterRegistry] = None) -> None:
        if core_registry is None:
            self._core_registry = AdapterRegistry()
            self._core_registry.register(CryptoScanAdapter())
            self._core_registry.register(SyftAdapter())
            self._core_registry.register(DemoSourceAdapter())
        else:
            self._core_registry = core_registry
            if not self._core_registry.has("demo_source_adapter"):
                self._core_registry.register(DemoSourceAdapter())

        self._status_registry: Dict[str, AdapterStatusInfo] = {}
        self._init_adapter_statuses()

    def _init_adapter_statuses(self) -> None:
        # LIVE adapters in product/core/ingestion/adapters/ and demo/adapters/
        self._status_registry["cryptoscan"] = AdapterStatusInfo(
            adapter_id="cryptoscan",
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            status=CapabilityClassification.LIVE,
            description="Static AST and semantic regex discovery adapter for Java and Python source repositories.",
            supported_formats=["json"],
            limitations="Benchmark TC08/TC11 scanner false negatives observed in raw outputs; empty findings do not imply safety.",
        )
        self._status_registry["syft"] = AdapterStatusInfo(
            adapter_id="syft",
            scanner_name="Syft",
            scanner_version="1.51.1",
            status=CapabilityClassification.LIVE,
            description="Software Bill of Materials (SBOM) dependency scanner adapter cataloging package-level crypto libraries.",
            supported_formats=["json"],
            limitations="Detects library presence only; does not provide direct evidence of algorithm usage.",
        )
        self._status_registry["demo_source_adapter"] = AdapterStatusInfo(
            adapter_id="demo_source_adapter",
            scanner_name="DemoSourceScanner",
            scanner_version="1.0.0-demo",
            status=CapabilityClassification.LIVE,
            description="Bounded demonstration Java source code scanner inspecting real Java files for RSA, AES, and Ed25519 patterns.",
            supported_formats=["java", "zip"],
            limitations="Explicitly bounded to demonstration cryptographic constructs (RSA KeyPairGenerator, AES Cipher/SecretKeySpec, Ed25519 Signature). Does not perform whole-enterprise semantic analysis.",
        )

        # ARCHITECTURAL / FUTURE adapters (Planned but not commissioned in Phase 4)
        self._status_registry["sonar"] = AdapterStatusInfo(
            adapter_id="sonar",
            scanner_name="Sonar Cryptography Plugin",
            scanner_version="1.6.1 (Planned)",
            status=CapabilityClassification.ARCHITECTURAL,
            description="Enterprise SonarQube plugin ingestion adapter for CI/CD cryptographic gatekeeping.",
            supported_formats=["json", "xml"],
            limitations="Execution blocked during Phase 1C-B; architectural boundary defined, live parser deferred.",
        )
        self._status_registry["codeql"] = AdapterStatusInfo(
            adapter_id="codeql",
            scanner_name="GitHub CodeQL",
            scanner_version="Enterprise (Planned)",
            status=CapabilityClassification.ARCHITECTURAL,
            description="Deep semantic data-flow and taint tracking query adapter for cryptographic primitives.",
            supported_formats=["sarif"],
            limitations="Proprietary engine; requires customer license and external SARIF ingestion pipeline.",
        )
        self._status_registry["sslscan"] = AdapterStatusInfo(
            adapter_id="sslscan",
            scanner_name="sslscan2",
            scanner_version="2.1.3 (Planned)",
            status=CapabilityClassification.ARCHITECTURAL,
            description="Network TLS endpoint and cipher suite negotiation discovery adapter.",
            supported_formats=["xml"],
            limitations="GPLv3 license prevents direct bundling; requires air-gapped container execution.",
        )

    @property
    def core_registry(self) -> AdapterRegistry:
        """Returns the real underlying frozen product AdapterRegistry."""
        return self._core_registry

    def get_status(self, adapter_id: str) -> Optional[AdapterStatusInfo]:
        return self._status_registry.get(adapter_id)

    def list_adapters(self) -> List[AdapterStatusInfo]:
        """Lists all adapters in deterministic order."""
        return [self._status_registry[k] for k in sorted(self._status_registry.keys())]

    def is_live(self, adapter_id: str) -> bool:
        status = self.get_status(adapter_id)
        return status is not None and status.status == CapabilityClassification.LIVE
