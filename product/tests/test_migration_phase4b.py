"""
ECDAT Unit & Integration Test Suite for Phase 4B: Hybrid Transition Schemes & Migration Scheduling.

Tests all aspects of:
- Standards-grounded hybrid evaluation (Protocol-level KEM vs Composite signatures vs Dual-cert PKI)
- Exact standards status tracking (STANDARDIZED vs DRAFT vs PROFILE_DEPLOYMENT_PATTERN)
- Construction-specific conditional security semantics (NO universal max-security claims)
- Role separation (KEM vs Signature vs Symmetric vs Hash)
- Data-at-rest separation (AES-256 is not replaced by KEM)
- DAG-based topological dependency scheduling
- Dependency cycle detection and review gate generation
- HNDL risk-aware milestone prioritization
- Agility blocker generation (CODE_REFACTOR_REQUIRED for hardcoded literals)
- Review gates for uncertain/conditional/unparameterized assets
- Input immutability and execution determinism
"""

import unittest
from typing import Optional

from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity
from product.core.domain.asset import AssetType, CryptoAsset
from product.core.domain.confidence import ConfidenceLevel
from product.core.domain.parameters import AlgorithmParameters
from product.core.domain.role import CryptographicRole
from product.core.evidence.evidence import EvidenceLocation, LocationType, SourceLocation
from product.core.migration import (
    AgilityLevel,
    ClassicalSecurityStrength,
    HybridConstructionType,
    HybridSchemeCandidate,
    MigrationMilestone,
    MigrationPhase,
    MigrationSchedule,
    MigrationScheduler,
    PqcSecurityCategory,
    PqcTargetFamily,
    PqcTargetMapper,
    PqcTargetMapping,
    ReviewGate,
    StandardsStatus,
    TargetMappingStatus,
    evaluate_hybrid_options,
)


class TestMigrationPhase4B(unittest.TestCase):
    """Test suite for Phase 4B Hybrid Schemes & Migration Scheduling."""

    def setUp(self) -> None:
        self.mapper = PqcTargetMapper()
        self.scheduler = MigrationScheduler(self.mapper)

    def _create_mock_asset(
        self,
        asset_id: str = "asset-01",
        algo_name: str = "RSA",
        family: AlgorithmFamily = AlgorithmFamily.RSA,
        role: CryptographicRole = CryptographicRole.KEY_GENERATION,
        key_size: Optional[int] = 2048,
        curve_name: Optional[str] = None,
        cipher_mode: Optional[str] = None,
        asset_type: AssetType = AssetType.ALGORITHM,
        confidence: ConfidenceLevel = ConfidenceLevel.CONFIRMED,
        file_path: str = "src/SecurityService.java",
        matched_text: str = 'KeyPairGenerator.getInstance("RSA");',
        code_snippet: str = 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
    ) -> CryptoAsset:
        return CryptoAsset(
            asset_id=asset_id,
            asset_type=asset_type,
            algorithm_identity=AlgorithmIdentity(family=family, algorithm=algo_name),
            role=role,
            parameters=AlgorithmParameters(
                key_size_bits=key_size,
                curve_name=curve_name,
                cipher_mode=cipher_mode,
            ),
            finding_ids=["find-01"],
            primary_location=SourceLocation(
                file_path=file_path,
                line_start=15,
                line_end=16,
                matched_text=matched_text,
                code_snippet=code_snippet,
            ),
            confidence=confidence,
            correlation_basis="test_fixture",
        )

    # =========================================================================
    # 1. Hybrid Evaluation Tests
    # =========================================================================

    def test_01_x25519_key_agreement_maps_to_draft_x25519_mlkem768(self) -> None:
        """Verifies X25519 key agreement maps to draft-ietf-tls-hybrid-design X25519MLKEM768."""
        asset = self._create_mock_asset(
            algo_name="X25519",
            family=AlgorithmFamily.EDWARDS,
            role=CryptographicRole.KEY_AGREEMENT,
            curve_name="curve25519",
        )
        candidates = evaluate_hybrid_options(asset)
        self.assertTrue(len(candidates) >= 1)

        c = next((x for x in candidates if x.scheme_name == "X25519MLKEM768"), None)
        self.assertIsNotNone(c)
        self.assertEqual(c.construction_type, HybridConstructionType.PROTOCOL_LEVEL_KEM)
        self.assertEqual(c.standards_status, StandardsStatus.DRAFT)
        self.assertIn("draft-ietf-tls-hybrid-design", c.standards_reference)
        self.assertIn("X25519", c.classical_component)
        self.assertIn("ML-KEM-768", c.pqc_component)
        self.assertIsNotNone(c.overhead_bytes)

    def test_02_p256_ecdh_maps_to_draft_secp256r1_mlkem768(self) -> None:
        """Verifies NIST P-256 ECDH maps to SecP256r1MLKEM768 for FIPS profiles."""
        asset = self._create_mock_asset(
            algo_name="ECDH",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.KEY_AGREEMENT,
            curve_name="secp256r1",
        )
        candidates = evaluate_hybrid_options(asset)
        c = next((x for x in candidates if x.scheme_name == "SecP256r1MLKEM768"), None)
        self.assertIsNotNone(c)
        self.assertEqual(c.construction_type, HybridConstructionType.PROTOCOL_LEVEL_KEM)
        self.assertEqual(c.standards_status, StandardsStatus.DRAFT)

    def test_03_rsa_key_establishment_does_not_become_x25519(self) -> None:
        """Verifies RSA key transport does NOT falsely map to X25519MLKEM768; maps to dual-wrap envelope."""
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=2048,
        )
        candidates = evaluate_hybrid_options(asset)
        scheme_names = [x.scheme_name for x in candidates]
        self.assertNotIn("X25519MLKEM768", scheme_names)
        self.assertIn("RSA_OAEP_MLKEM768_DUAL_WRAP", scheme_names)

        c = next(x for x in candidates if x.scheme_name == "RSA_OAEP_MLKEM768_DUAL_WRAP")
        self.assertEqual(c.construction_type, HybridConstructionType.APPLICATION_ENVELOPE)
        self.assertEqual(c.standards_status, StandardsStatus.PROFILE_DEPLOYMENT_PATTERN)

    def test_04_signature_asset_maps_to_signature_candidate_not_kem(self) -> None:
        """Verifies digital signature asset maps to composite signature, never a KEM."""
        asset = self._create_mock_asset(
            algo_name="ECDSA",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            curve_name="secp256r1",
        )
        candidates = evaluate_hybrid_options(asset)
        for c in candidates:
            self.assertNotEqual(c.construction_type, HybridConstructionType.PROTOCOL_LEVEL_KEM)
            self.assertIn(c.construction_type, (HybridConstructionType.COMPOSITE_SIGNATURE, HybridConstructionType.DUAL_CERTIFICATE))

    def test_05_rsa_signature_maps_to_composite_and_dual_cert(self) -> None:
        """Verifies RSA signature maps to composite signature and dual-certificate options."""
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            key_size=3072,
        )
        candidates = evaluate_hybrid_options(asset)
        names = [x.scheme_name for x in candidates]
        self.assertIn("MLDSA65-RSA3072-PKCS15", names)
        self.assertIn("DUAL_CERT_RSA_MLDSA65", names)

    def test_06_ecdsa_signature_maps_to_mldsa65_composite_and_slhdsa_hedge(self) -> None:
        """Verifies ECDSA maps to MLDSA65-ECDSA-P256-SHA512 and hash-based SLHDSA128s-ECDSA-P256."""
        asset = self._create_mock_asset(
            algo_name="ECDSA",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            curve_name="secp256r1",
        )
        candidates = evaluate_hybrid_options(asset)
        names = [x.scheme_name for x in candidates]
        self.assertIn("MLDSA65-ECDSA-P256-SHA512", names)
        self.assertIn("SLHDSA128s-ECDSA-P256", names)

    def test_07_symmetric_aes_returns_none_for_public_hybrid(self) -> None:
        """Verifies AES bulk data encryption returns zero public-key hybrid candidates."""
        asset = self._create_mock_asset(
            algo_name="AES",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=256,
        )
        candidates = evaluate_hybrid_options(asset)
        self.assertEqual(len(candidates), 0)

    def test_08_sha_hash_returns_none_for_public_hybrid(self) -> None:
        """Verifies hash functions return zero public-key hybrid candidates."""
        asset = self._create_mock_asset(
            algo_name="SHA-256",
            family=AlgorithmFamily.SHA1,
            role=CryptographicRole.MESSAGE_DIGEST,
            key_size=None,
        )
        candidates = evaluate_hybrid_options(asset)
        self.assertEqual(len(candidates), 0)

    def test_09_unknown_role_returns_empty_hybrid_candidates(self) -> None:
        """Verifies unknown role fails closed with empty hybrid candidates."""
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.UNKNOWN,
            key_size=2048,
        )
        candidates = evaluate_hybrid_options(asset)
        self.assertEqual(len(candidates), 0)

    def test_10_dynamic_algorithm_returns_empty_hybrid_candidates(self) -> None:
        """Verifies dynamic unresolved algorithms fail closed with empty hybrid candidates."""
        asset = self._create_mock_asset(
            algo_name="dynamic_resolver()",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.KEY_AGREEMENT,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
        )
        candidates = evaluate_hybrid_options(asset)
        self.assertEqual(len(candidates), 0)

    def test_11_library_dependency_returns_empty_hybrid_candidates(self) -> None:
        """Verifies package dependency manifests return zero hybrid candidates."""
        asset = CryptoAsset(
            asset_id="pkg-01",
            asset_type=AssetType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="bcprov"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=["find-pkg"],
            primary_location=EvidenceLocation(location_type=LocationType.DEPENDENCY, package_coordinate="pkg:maven/bcprov"),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="manifest",
        )
        candidates = evaluate_hybrid_options(asset)
        self.assertEqual(len(candidates), 0)

    def test_12_rfc9370_ikev2_is_labeled_standardized(self) -> None:
        """Verifies RFC 9370 IKEv2 multiple key exchanges is marked STANDARDIZED."""
        asset = self._create_mock_asset(
            algo_name="ECDH",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.KEY_AGREEMENT,
            curve_name="secp256r1",
        )
        candidates = evaluate_hybrid_options(asset)
        ike = next((x for x in candidates if "RFC 9370" in x.standards_reference), None)
        self.assertIsNotNone(ike)
        self.assertEqual(ike.standards_status, StandardsStatus.STANDARDIZED)

    # =========================================================================
    # 2. Security Semantics Tests
    # =========================================================================

    def test_13_no_universal_max_security_claim_encoded(self) -> None:
        """Verifies no scheme candidate makes an unconditional 'Security >= max' claim."""
        asset = self._create_mock_asset(
            algo_name="X25519",
            family=AlgorithmFamily.EDWARDS,
            role=CryptographicRole.KEY_AGREEMENT,
            curve_name="curve25519",
        )
        candidates = evaluate_hybrid_options(asset)
        for c in candidates:
            self.assertNotIn("Security >= max", c.security_property)
            self.assertNotIn("automatically provides maximum security", c.security_property)

    def test_14_security_property_is_construction_specific(self) -> None:
        """Verifies security property explicitly documents dual-PRF or dual-verification assumptions."""
        asset_kem = self._create_mock_asset(algo_name="X25519", role=CryptographicRole.KEY_AGREEMENT, curve_name="curve25519")
        asset_sig = self._create_mock_asset(algo_name="ECDSA", role=CryptographicRole.DIGITAL_SIGNATURE, curve_name="secp256r1")

        cand_kem = evaluate_hybrid_options(asset_kem)[0]
        cand_sig = evaluate_hybrid_options(asset_sig)[0]

        self.assertIn("dual-PRF", cand_kem.security_property)
        self.assertIn("Dual-verification semantics", cand_sig.security_property)

    def test_15_draft_status_is_preserved_for_ietf_drafts(self) -> None:
        """Verifies TLS hybrid design and LAMPS composite drafts are marked DRAFT."""
        asset = self._create_mock_asset(algo_name="X25519", role=CryptographicRole.KEY_AGREEMENT, curve_name="curve25519")
        c = evaluate_hybrid_options(asset)[0]
        self.assertEqual(c.standards_status, StandardsStatus.DRAFT)

    def test_16_candidates_are_not_confused_with_approved_targets(self) -> None:
        """Verifies candidates carry confidence_status = CANDIDATE_EVALUATION, never APPROVED."""
        asset = self._create_mock_asset(algo_name="X25519", role=CryptographicRole.KEY_AGREEMENT, curve_name="curve25519")
        candidates = evaluate_hybrid_options(asset)
        for c in candidates:
            self.assertEqual(c.confidence_status, "CANDIDATE_EVALUATION")
            self.assertNotEqual(c.confidence_status, "APPROVED_TARGET")

    def test_17_compatibility_assumptions_remain_explicit(self) -> None:
        """Verifies compatibility assumptions disclose public key size and MTU fragmentation."""
        asset = self._create_mock_asset(algo_name="X25519", role=CryptographicRole.KEY_AGREEMENT, curve_name="curve25519")
        c = evaluate_hybrid_options(asset)[0]
        self.assertTrue(len(c.compatibility_assumptions) >= 2)
        self.assertTrue(any("ClientHello" in a for a in c.compatibility_assumptions))

    # =========================================================================
    # 3. Migration Scheduling Tests
    # =========================================================================

    def test_18_real_dependency_ordering(self) -> None:
        """Verifies application crypto asset depends on library provider asset in dependency graph."""
        lib_asset = CryptoAsset(
            asset_id="lib-bouncycastle",
            asset_type=AssetType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="bouncycastle"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=["f-pkg"],
            primary_location=EvidenceLocation(location_type=LocationType.DEPENDENCY, package_coordinate="pkg:maven/bcprov"),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="manifest",
        )
        app_asset = self._create_mock_asset(
            asset_id="app-ecdh",
            algo_name="ECDH",
            role=CryptographicRole.KEY_AGREEMENT,
            curve_name="secp256r1",
            file_path="src/bouncycastle/CryptoService.java",
        )

        schedule = self.scheduler.schedule_migration([lib_asset, app_asset])
        self.assertIn("lib-bouncycastle", schedule.dependency_graph["app-ecdh"])

    def test_19_library_prerequisite_is_in_milestone_1_preparation(self) -> None:
        """Verifies library package assets are grouped into Milestone 1 PREPARATION."""
        lib_asset = CryptoAsset(
            asset_id="lib-01",
            asset_type=AssetType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="openssl"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=["f-pkg"],
            primary_location=EvidenceLocation(location_type=LocationType.DEPENDENCY, package_coordinate="pkg:deb/openssl"),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="manifest",
        )
        schedule = self.scheduler.schedule_migration([lib_asset])
        m1 = next((m for m in schedule.milestones if m.phase == MigrationPhase.PREPARATION), None)
        self.assertIsNotNone(m1)
        self.assertIn("lib-01", m1.target_asset_ids)

    def test_20_hndl_evidence_influences_grouping_and_priority(self) -> None:
        """Verifies key agreement assets are placed in Milestone 2 KEY_EXCHANGE_HNDL."""
        asset = self._create_mock_asset(
            asset_id="asset-ecdh",
            algo_name="ECDH",
            role=CryptographicRole.KEY_AGREEMENT,
            curve_name="secp256r1",
        )
        schedule = self.scheduler.schedule_migration([asset])
        m2 = next((m for m in schedule.milestones if m.phase == MigrationPhase.KEY_EXCHANGE_HNDL), None)
        self.assertIsNotNone(m2)
        self.assertIn("asset-ecdh", m2.target_asset_ids)
        self.assertIn("asset-ecdh", schedule.hndl_prioritized_assets)

    def test_21_missing_hndl_information_does_not_become_true(self) -> None:
        """Verifies symmetric AES without HNDL context is NOT marked as HNDL-prioritized."""
        asset = self._create_mock_asset(
            asset_id="asset-aes",
            algo_name="AES",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=256,
        )
        schedule = self.scheduler.schedule_migration([asset])
        self.assertNotIn("asset-aes", schedule.hndl_prioritized_assets)

    def test_22_hardcoded_agility_produces_a_blocker(self) -> None:
        """Verifies AgilityLevel.HARDCODED produces CODE_REFACTOR_REQUIRED blocker."""
        asset = self._create_mock_asset(
            asset_id="hardcoded-asset",
            matched_text='Cipher.getInstance("RSA/ECB/PKCS1Padding");',
            code_snippet='Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");',
        )
        schedule = self.scheduler.schedule_migration([asset])
        self.assertIn("hardcoded-asset", schedule.blocked_assets)
        self.assertEqual(schedule.schedule_status, "ADVISORY_PENDING_REVIEW")

        m = schedule.milestones[0]
        self.assertTrue(any("CODE_REFACTOR_REQUIRED" in b for b in m.blockers))

    def test_23_needs_review_creates_a_review_gate(self) -> None:
        """Verifies an asset with NEEDS_REVIEW mapping produces a formal ReviewGate."""
        asset = self._create_mock_asset(
            asset_id="ambiguous-asset",
            algo_name="UNKNOWN_ALGO",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
        )
        schedule = self.scheduler.schedule_migration([asset])
        self.assertTrue(len(schedule.review_gates) >= 1)
        gate = next((g for g in schedule.review_gates if g.asset_id == "ambiguous-asset"), None)
        self.assertIsNotNone(gate)
        self.assertIn("missing_information", gate.to_dict())
        self.assertIn("consequence_if_unresolved", gate.to_dict())

    def test_24_conditional_mapping_creates_a_review_gate(self) -> None:
        """Verifies unannotated parameters (CONDITIONAL mapping) produces a ReviewGate."""
        asset = self._create_mock_asset(
            asset_id="unannotated-rsa",
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.KEY_AGREEMENT,
            key_size=None,  # missing key size!
        )
        schedule = self.scheduler.schedule_migration([asset])
        gate = next((g for g in schedule.review_gates if g.asset_id == "unannotated-rsa"), None)
        self.assertIsNotNone(gate)

    def test_25_dependency_cycles_are_detected_and_preserved(self) -> None:
        """Verifies circular dependencies are detected, preserved, and mark schedule BLOCKED_DEPENDENCY_CYCLE."""
        a1 = self._create_mock_asset(asset_id="asset-1", algo_name="RSA", role=CryptographicRole.KEY_AGREEMENT)
        a2 = self._create_mock_asset(asset_id="asset-2", algo_name="ECDSA", role=CryptographicRole.DIGITAL_SIGNATURE)

        # Create cycle: a1 -> a2 and a2 -> a1
        explicit_deps = {"asset-1": ["asset-2"], "asset-2": ["asset-1"]}
        schedule = self.scheduler.schedule_migration([a1, a2], explicit_dependencies=explicit_deps)

        self.assertEqual(schedule.schedule_status, "BLOCKED_DEPENDENCY_CYCLE")
        self.assertTrue(len(schedule.dependency_cycles) >= 1)
        self.assertIn("asset-1", schedule.blocked_assets)
        self.assertIn("asset-2", schedule.blocked_assets)
        self.assertTrue(any("GATE-CYCLE" in g.gate_id for g in schedule.review_gates))

    def test_26_independent_assets_are_not_artificially_chained(self) -> None:
        """Verifies unrelated independent assets do not have mutual prerequisites in dependency_graph."""
        a1 = self._create_mock_asset(asset_id="asset-independent-1", algo_name="RSA", role=CryptographicRole.DIGITAL_SIGNATURE)
        a2 = self._create_mock_asset(asset_id="asset-independent-2", algo_name="ECDH", role=CryptographicRole.KEY_AGREEMENT)

        schedule = self.scheduler.schedule_migration([a1, a2])
        self.assertEqual(len(schedule.dependency_graph["asset-independent-1"]), 0)
        self.assertEqual(len(schedule.dependency_graph["asset-independent-2"]), 0)

    def test_27_missing_operational_evidence_remains_unresolved(self) -> None:
        """Verifies missing operational evidence is explicitly recorded in unresolved_items."""
        asset = self._create_mock_asset(
            asset_id="unresolved-asset",
            algo_name="RSA",
            role=CryptographicRole.UNKNOWN,
            confidence=ConfidenceLevel.NEEDS_REVIEW,
        )
        schedule = self.scheduler.schedule_migration([asset])
        m = schedule.milestones[0]
        self.assertTrue(any("requires human validation" in u for u in m.unresolved_items))

    def test_28_deterministic_output_and_immutability(self) -> None:
        """Verifies repeated execution on equivalent assets produces byte-identical outputs without mutation."""
        a1 = self._create_mock_asset(asset_id="a-01", algo_name="RSA", role=CryptographicRole.KEY_AGREEMENT)
        a2 = self._create_mock_asset(asset_id="a-02", algo_name="AES", family=AlgorithmFamily.AES, role=CryptographicRole.ENCRYPTION_DECRYPTION)

        s1 = self.scheduler.schedule_migration([a1, a2])
        s2 = self.scheduler.schedule_migration([a1, a2])

        self.assertEqual(s1.to_dict(), s2.to_dict())

        # Test immutability
        with self.assertRaises((AttributeError, TypeError)):
            s1.schedule_status = "MODIFIED"  # type: ignore

    # =========================================================================
    # 4. Data-At-Rest Correction Tests
    # =========================================================================

    def test_29_aes_256_is_not_automatically_replaced_by_a_kem(self) -> None:
        """Verifies AES-256 data encryption is placed in Milestone 4 DATA_AT_REST, NOT hybrid KEM."""
        asset = self._create_mock_asset(
            asset_id="storage-aes",
            algo_name="AES",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=256,
        )
        mapping = self.mapper.map_asset(asset)
        schedule = self.scheduler.schedule_migration([asset], target_mappings=[mapping])

        # Hybrid candidates must be empty
        self.assertEqual(len(mapping.hybrid_candidates), 0)

        # Milestone must be DATA_AT_REST, not KEY_EXCHANGE_HNDL
        m = next((m for m in schedule.milestones if "storage-aes" in m.target_asset_ids), None)
        self.assertIsNotNone(m)
        self.assertEqual(m.phase, MigrationPhase.DATA_AT_REST)

    def test_30_target_mapper_populates_hybrid_candidates(self) -> None:
        """Verifies PqcTargetMapper.map_asset populates hybrid_candidates field automatically."""
        asset = self._create_mock_asset(
            algo_name="X25519",
            family=AlgorithmFamily.EDWARDS,
            role=CryptographicRole.KEY_AGREEMENT,
            curve_name="curve25519",
        )
        res = self.mapper.map_asset(asset)
        self.assertTrue(len(res.hybrid_candidates) >= 1)
        self.assertEqual(res.hybrid_candidates[0].scheme_name, "X25519MLKEM768")
        self.assertEqual(res.hybrid_candidates[0].standards_status, StandardsStatus.DRAFT)

    # =========================================================================
    # 5. Standards Correction & Refined Taxonomy Tests
    # =========================================================================

    def test_31_sp800_227_and_rfc9763_authoritative_standards_citations(self) -> None:
        """Verifies authoritative citations: NIST SP 800-227 Final (Sept 2025) and RFC 9763."""
        # 1. RSA Dual Wrap cites SP 800-227 Final
        rsa_asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=2048,
        )
        rsa_cands = evaluate_hybrid_options(rsa_asset)
        wrap_cand = next((c for c in rsa_cands if c.scheme_name == "RSA_OAEP_MLKEM768_DUAL_WRAP"), None)
        self.assertIsNotNone(wrap_cand)
        self.assertIn("NIST SP 800-227", wrap_cand.standards_reference)
        self.assertIn("Final", wrap_cand.standards_reference)

        # 2. Dual Cert cites RFC 9763
        ecdsa_asset = self._create_mock_asset(
            algo_name="ECDSA",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            curve_name="secp256r1",
        )
        ecdsa_cands = evaluate_hybrid_options(ecdsa_asset)
        dual_cert_cand = next((c for c in ecdsa_cands if c.construction_type == HybridConstructionType.DUAL_CERTIFICATE), None)
        self.assertIsNotNone(dual_cert_cand)
        self.assertIn("RFC 9763", dual_cert_cand.standards_reference)

    def test_32_hybrid_kem_security_property_articulates_passive_vs_active_and_downgrade(self) -> None:
        """Verifies hybrid KEM security property distinguishes passive HNDL from active attacks and notes downgrade."""
        asset = self._create_mock_asset(
            algo_name="X25519",
            family=AlgorithmFamily.EDWARDS,
            role=CryptographicRole.KEY_AGREEMENT,
            curve_name="curve25519",
        )
        cands = evaluate_hybrid_options(asset)
        x25519_cand = next((c for c in cands if c.scheme_name == "X25519MLKEM768"), None)
        self.assertIsNotNone(x25519_cand)
        # Must articulate passive HNDL
        self.assertIn("passive", x25519_cand.security_property.lower())
        self.assertIn("hndl", x25519_cand.security_property.lower())
        # Must explicitly state it does NOT provide active security if authentication is classical
        self.assertIn("active", x25519_cand.security_property.lower())
        # Must mention downgrade protection
        self.assertIn("downgrade", x25519_cand.security_property.lower())

    def test_33_composite_signatures_versus_dual_certificates_taxonomy(self) -> None:
        """Verifies distinct taxonomy between composite signatures, dual signatures, and dual certificates."""
        # Ensure distinct enum values exist in HybridConstructionType
        self.assertNotEqual(HybridConstructionType.COMPOSITE_SIGNATURE, HybridConstructionType.DUAL_CERTIFICATE)
        self.assertNotEqual(HybridConstructionType.COMPOSITE_SIGNATURE, HybridConstructionType.DUAL_SIGNATURE)
        self.assertNotEqual(HybridConstructionType.DUAL_CERTIFICATE, HybridConstructionType.DUAL_SIGNATURE)

        # Composite signature must note dual-verification and composite OID requirement
        asset = self._create_mock_asset(
            algo_name="ECDSA",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            curve_name="secp256r1",
        )
        cands = evaluate_hybrid_options(asset)
        comp_cand = next((c for c in cands if c.construction_type == HybridConstructionType.COMPOSITE_SIGNATURE), None)
        self.assertIsNotNone(comp_cand)
        self.assertIn("Dual-verification", comp_cand.security_property)
        self.assertIn("composite", comp_cand.security_property.lower())

        # Dual cert must note partitioned security
        dual_cert = next((c for c in cands if c.construction_type == HybridConstructionType.DUAL_CERTIFICATE), None)
        self.assertIsNotNone(dual_cert)
        self.assertIn("partitioned", dual_cert.security_property.lower())

    def test_34_invalid_unsupported_scheme_identifier_returns_unverified_and_none(self) -> None:
        """Verifies StandardsStatus and HybridConstructionType gracefully fail closed to safe defaults."""
        self.assertEqual(StandardsStatus.from_str("NONEXISTENT_DRAFT_STATUS"), StandardsStatus.UNVERIFIED)
        self.assertEqual(StandardsStatus.from_str(None), StandardsStatus.UNVERIFIED)
        self.assertEqual(StandardsStatus.from_str(""), StandardsStatus.UNVERIFIED)

        self.assertEqual(HybridConstructionType.from_str("NONEXISTENT_TYPE"), HybridConstructionType.NONE)
        self.assertEqual(HybridConstructionType.from_str(None), HybridConstructionType.NONE)
        self.assertEqual(HybridConstructionType.from_str(""), HybridConstructionType.NONE)


if __name__ == "__main__":
    unittest.main()

