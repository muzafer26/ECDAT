"""
ECDAT Demo Scenario Registry.

Maintains controlled scenarios grounded strictly in existing repository benchmark fixtures.
"""

from pathlib import Path
from typing import Dict, List, Optional
from .models import DemoScenario, ScenarioClassification


class ScenarioRegistry:
    """Registry of verified demonstration scenarios."""

    def __init__(self, workspace_root: Optional[Path] = None) -> None:
        self.workspace_root = workspace_root or Path(__file__).resolve().parent.parent.parent
        self._scenarios: Dict[str, DemoScenario] = {}
        self._register_default_scenarios()

    def _register_default_scenarios(self) -> None:
        # Scenario 1: TC01 - Direct RSA-2048 Key Generation (Hero Scenario Foundation)
        tc01_path = self.workspace_root / "product" / "benchmark" / "tools" / "raw_outputs" / "cryptoscan" / "tc01_direct_rsa" / "run1_output.json"
        self.register(
            DemoScenario(
                scenario_id="tc01_direct_rsa",
                name="Direct RSA Keypair Generation",
                description="Asymmetric RSA key generation in Java source. Demonstrates evidence-driven uncertainty: CryptoScan captured algorithm instantiation without key size; benchmark ground truth indicates 2048-bit modulus, but ECDAT evaluates classical security to INDETERMINATE and routes to P_REVIEW_REQUIRED.",
                target_name="tc01-direct-rsa",
                adapter_id="cryptoscan",
                fixture_path=tc01_path,
                classification=ScenarioClassification.LIVE,
                expected_primary_family="RSA",
                expected_min_assets=1,
                metadata={
                    "benchmark_id": "TC-01",
                    "primitive": "pke",
                    "pqc_eligible": True,
                    "organization": "Global FinTech Enterprise (Demo Scope)",
                    "system": "Payment Gateway & Ingestion API",
                    "component": "Session Key Negotiation Service",
                    "business_criticality": "Tier 1 Mission-Critical",
                    "data_sensitivity": "Financial Session Keys & Secrets",
                    "data_lifetime": "5 to 10 Years (HNDL Window)",
                    "network_exposure": "Internet-Facing Public Endpoint",
                    "environment": "production",
                },
            )
        )

        # Scenario 2: TC02 - Symmetric AES (Out of Scope for PQC KEM)
        tc02_path = self.workspace_root / "product" / "benchmark" / "tools" / "raw_outputs" / "cryptoscan" / "tc02_symmetric_aes" / "run1_output.json"
        self.register(
            DemoScenario(
                scenario_id="tc02_symmetric_aes",
                name="Symmetric AES Cipher",
                description="Symmetric AES encryption in Java. Evaluates correctly to OUT_OF_SCOPE for PQC replacement, demonstrating truthful non-inference.",
                target_name="tc02-symmetric-aes",
                adapter_id="cryptoscan",
                fixture_path=tc02_path,
                classification=ScenarioClassification.LIVE,
                expected_primary_family="AES",
                expected_min_assets=2,
                metadata={
                    "benchmark_id": "TC-02",
                    "primitive": "symmetric_cipher",
                    "pqc_eligible": False,
                    "organization": "Global FinTech Enterprise (Demo Scope)",
                    "system": "Core Ledger & Storage Service",
                    "component": "Encrypted Database Block Storage",
                    "business_criticality": "Tier 1 Mission-Critical",
                    "data_sensitivity": "Restricted Customer Account Records",
                    "data_lifetime": "Persistent (> 10 Years)",
                    "network_exposure": "Internal VPC",
                    "environment": "production",
                },
            )
        )

        # Scenario 3: TC06 - Ed25519 Digital Signature (NIST FIPS 204/205 Mapping)
        tc06_path = self.workspace_root / "product" / "benchmark" / "tools" / "raw_outputs" / "cryptoscan" / "tc06_ed25519" / "run1_output.json"
        self.register(
            DemoScenario(
                scenario_id="tc06_ed25519",
                name="Ed25519 Digital Signature",
                description="Asymmetric Edwards-curve digital signature in Java. Maps role-specifically to NIST FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA), proving signature roles map to PQC signatures, not KEMs.",
                target_name="tc06-ed25519",
                adapter_id="cryptoscan",
                fixture_path=tc06_path,
                classification=ScenarioClassification.LIVE,
                expected_primary_family="EDWARDS",
                expected_min_assets=1,
                metadata={
                    "benchmark_id": "TC-06",
                    "primitive": "digital_signature",
                    "pqc_eligible": True,
                    "organization": "Global FinTech Enterprise (Demo Scope)",
                    "system": "PKI & Notarization Service",
                    "component": "Document & Audit Log Signature Engine",
                    "business_criticality": "Tier 2 Business Operational",
                    "data_sensitivity": "Audit Evidence & Authentication Tokens",
                    "data_lifetime": "Persistent / Legal Non-Repudiation",
                    "network_exposure": "Partner DMZ",
                    "environment": "production",
                },
            )
        )

    def register(self, scenario: DemoScenario) -> None:
        if scenario.scenario_id in self._scenarios:
            raise ValueError(f"Scenario with ID '{scenario.scenario_id}' already registered.")
        self._scenarios[scenario.scenario_id] = scenario

    def get(self, scenario_id: str) -> Optional[DemoScenario]:
        return self._scenarios.get(scenario_id)

    def list_scenarios(self) -> List[DemoScenario]:
        return [self._scenarios[k] for k in sorted(self._scenarios.keys())]
