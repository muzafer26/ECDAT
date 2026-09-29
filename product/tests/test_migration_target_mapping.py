"""
ECDAT Unit & Integration Test Suite for Phase 4A Migration Target Mapping & Standards Semantics.

Tests all aspects of:
- Strict separation between classical security strength (in bits) and NIST PQC security categories.
- Deterministic NIST FIPS 203/204/205 PQC target mapping.
- NIST SP 800-57 Part 1 Rev. 5 security-strength classification.
- Evidence-grounded cryptographic agility assessment.
- Role-aware separation (KEM vs Signature).
- Out-of-scope classification for symmetric ciphers and hashes.
- Fail-closed handling for unknown, ambiguous, and unparameterized primitives.
- Candidate vs approved target semantics.
- Non-mutation and deep immutability invariants.
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
    CandidateTarget,
    ClassicalSecurityStrength,
    NistSecurityCategory,
    PqcSecurityCategory,
    PqcTargetFamily,
    PqcTargetMapper,
    TargetMappingStatus,
    assess_cryptographic_agility,
    classify_classical_security_strength,
    classify_nist_security_strength,
)


class TestMigrationTargetMapping(unittest.TestCase):
    """Test suite for Phase 4A PQC target mapping, agility modeling, and standards semantics."""

    def setUp(self) -> None:
        self.mapper = PqcTargetMapper()

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
    # 1. Role-Aware Asymmetric Mapping Tests (KEM vs Signature)
    # =========================================================================

    def test_01_rsa_key_establishment_maps_to_fips_203_ml_kem(self) -> None:
        """Verifies RSA used for key establishment/transport maps to ML-KEM, NOT digital signatures."""
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=2048,
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.MAPPED)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.LEGACY_112)
        self.assertEqual(res.classical_bits, 112)
        self.assertEqual(res.target_equivalence_category, PqcSecurityCategory.CATEGORY_1)
        self.assertTrue(len(res.candidate_targets) >= 2)

        # Primary candidate must be ML-KEM
        fam_list = [t.family for t in res.candidate_targets]
        self.assertIn(PqcTargetFamily.ML_KEM, fam_list)
        self.assertNotIn(PqcTargetFamily.ML_DSA, fam_list)
        self.assertNotIn(PqcTargetFamily.SLH_DSA, fam_list)

        # Verify candidate target has explicit PQC category
        ml_kem_768 = next(t for t in res.candidate_targets if t.parameter_set == "ML-KEM-768")
        self.assertEqual(ml_kem_768.pqc_security_category, PqcSecurityCategory.CATEGORY_3)

        # Verify compatibility considerations are present
        self.assertTrue(any("encapsulates a random 32-byte shared secret" in c for c in res.compatibility_considerations))
        self.assertTrue(any("hybrid KEM + AEAD" in c for c in res.compatibility_considerations))

    def test_02_rsa_signature_maps_to_fips_204_and_205(self) -> None:
        """Verifies RSA used for signing maps to ML-DSA and SLH-DSA, NOT ML-KEM."""
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            key_size=2048,
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.MAPPED)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.LEGACY_112)
        self.assertEqual(res.classical_bits, 112)
        self.assertEqual(res.target_equivalence_category, PqcSecurityCategory.CATEGORY_1)

        fam_list = [t.family for t in res.candidate_targets]
        self.assertIn(PqcTargetFamily.ML_DSA, fam_list)
        self.assertIn(PqcTargetFamily.SLH_DSA, fam_list)
        self.assertNotIn(PqcTargetFamily.ML_KEM, fam_list)

        # Check signature expansion disclosures
        self.assertTrue(any("Signature size expansion" in c for c in res.compatibility_considerations))

    def test_03_ecdh_maps_to_fips_203_ml_kem(self) -> None:
        """Verifies ECDH key agreement maps to ML-KEM."""
        asset = self._create_mock_asset(
            algo_name="ECDH",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.KEY_AGREEMENT,
            curve_name="secp256r1",
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.MAPPED)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.BITS_128)
        self.assertEqual(res.classical_bits, 128)
        self.assertEqual(res.target_equivalence_category, PqcSecurityCategory.CATEGORY_1)
        self.assertTrue(all(t.family == PqcTargetFamily.ML_KEM for t in res.candidate_targets))

    def test_04_ecdsa_maps_to_ml_dsa_and_slh_dsa(self) -> None:
        """Verifies ECDSA signing maps to ML-DSA and SLH-DSA."""
        asset = self._create_mock_asset(
            algo_name="ECDSA",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            curve_name="secp256r1",
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.MAPPED)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.BITS_128)
        self.assertEqual(res.classical_bits, 128)
        self.assertEqual(res.target_equivalence_category, PqcSecurityCategory.CATEGORY_1)

        target_sets = [t.parameter_set for t in res.candidate_targets]
        self.assertIn("ML-DSA-65", target_sets)
        self.assertIn("ML-DSA-44", target_sets)
        self.assertIn("SLH-DSA-SHA2-128s", target_sets)

    def test_05_ed25519_maps_to_ml_dsa_and_slh_dsa(self) -> None:
        """Verifies Ed25519 signature maps to ML-DSA/SLH-DSA with expansion factor."""
        asset = self._create_mock_asset(
            algo_name="Ed25519",
            family=AlgorithmFamily.EDWARDS,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            curve_name="ed25519",
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.MAPPED)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.BITS_128)
        self.assertEqual(res.classical_bits, 128)
        self.assertTrue(any("Ed25519 signature (64 bytes) to ML-DSA-65" in c for c in res.compatibility_considerations))

    # =========================================================================
    # 2. Symmetric and Hash Non-Mapping Tests (Out of Scope for Public-Key PQC)
    # =========================================================================

    def test_06_symmetric_aes_is_out_of_scope_for_public_pqc(self) -> None:
        """Verifies AES is classified as OUT_OF_SCOPE for public-key PQC and suggests AES-256 expansion."""
        asset = self._create_mock_asset(
            algo_name="AES",
            family=AlgorithmFamily.AES,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=128,
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.OUT_OF_SCOPE)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.BITS_128)
        self.assertIsNone(res.target_equivalence_category)
        self.assertEqual(len(res.candidate_targets), 1)
        self.assertEqual(res.candidate_targets[0].family, PqcTargetFamily.AES_256_EXPANSION)
        self.assertEqual(res.candidate_targets[0].parameter_set, "AES-256")
        self.assertIn("Grover", res.candidate_targets[0].rationale)

    def test_07_sha1_hash_is_out_of_scope_for_public_pqc(self) -> None:
        """Verifies SHA-1 hash is OUT_OF_SCOPE for public-key PQC and suggests SHA-256/SHA-3."""
        asset = self._create_mock_asset(
            algo_name="SHA-1",
            family=AlgorithmFamily.SHA1,
            role=CryptographicRole.MESSAGE_DIGEST,
            key_size=None,
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.OUT_OF_SCOPE)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.DISALLOWED_SUB_112)
        self.assertIsNone(res.target_equivalence_category)
        self.assertEqual(len(res.candidate_targets), 1)
        self.assertEqual(res.candidate_targets[0].family, PqcTargetFamily.SHA2_OR_SHA3)

    def test_07b_library_dependency_is_out_of_scope(self) -> None:
        """Verifies package dependency assets are classified as OUT_OF_SCOPE."""
        asset = CryptoAsset(
            asset_id="dep-01",
            asset_type=AssetType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="bouncycastle"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=["find-pkg"],
            primary_location=EvidenceLocation(location_type=LocationType.DEPENDENCY, package_coordinate="pkg:maven/org.bouncycastle/bcprov-jdk18on"),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="manifest",
        )
        res = self.mapper.map_asset(asset)
        self.assertEqual(res.mapping_status, TargetMappingStatus.OUT_OF_SCOPE)
        self.assertEqual(len(res.candidate_targets), 0)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.OUT_OF_SCOPE)

    # =========================================================================
    # 3. Fail-Closed Handling for Unknown, Ambiguous, and Unparameterized Primitives
    # =========================================================================

    def test_08_unknown_algorithm_evaluates_to_needs_review(self) -> None:
        """Verifies AlgorithmFamily.UNKNOWN evaluates to NEEDS_REVIEW with zero candidate targets."""
        asset = self._create_mock_asset(
            algo_name="UNKNOWN",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=None,
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.NEEDS_REVIEW)
        self.assertEqual(len(res.candidate_targets), 0)
        self.assertTrue(res.required_human_review)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.INDETERMINATE)
        self.assertIsNone(res.target_equivalence_category)

    def test_09_bare_rijndael_evaluates_to_needs_review(self) -> None:
        """Verifies bare 'Rijndael' without 128-bit block size evidence evaluates to NEEDS_REVIEW."""
        asset = self._create_mock_asset(
            algo_name="Rijndael",
            family=AlgorithmFamily.UNKNOWN,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=None,
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.NEEDS_REVIEW)
        self.assertEqual(len(res.candidate_targets), 0)
        self.assertTrue(res.required_human_review)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.INDETERMINATE)

    def test_10_missing_parameters_evaluates_to_conditional(self) -> None:
        """Verifies RSA with missing modulus key size produces CONDITIONAL mapping, not silent drop-in."""
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=None,  # Missing key size!
        )
        res = self.mapper.map_asset(asset)

        self.assertEqual(res.mapping_status, TargetMappingStatus.CONDITIONAL)
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.INDETERMINATE)
        self.assertIsNone(res.classical_bits)
        self.assertIsNone(res.target_equivalence_category)
        self.assertTrue(res.required_human_review)
        self.assertTrue(any("unannotated" in r or "unverified" in r for r in res.unmapped_reasons))

    # =========================================================================
    # 4. NIST Classical Security Strength Boundary Tests
    # =========================================================================

    def test_11_nist_classical_security_strength_boundaries(self) -> None:
        """Verifies NIST SP 800-57 Part 1 Rev. 5 Table 2 classical security strength boundary mappings."""
        test_cases = [
            # RSA
            ("RSA", AlgorithmFamily.RSA, 1024, None, ClassicalSecurityStrength.DISALLOWED_SUB_112, 80),
            ("RSA", AlgorithmFamily.RSA, 2048, None, ClassicalSecurityStrength.LEGACY_112, 112),
            ("RSA", AlgorithmFamily.RSA, 3072, None, ClassicalSecurityStrength.BITS_128, 128),
            ("RSA", AlgorithmFamily.RSA, 4096, None, ClassicalSecurityStrength.BITS_128, 140),
            ("RSA", AlgorithmFamily.RSA, 7680, None, ClassicalSecurityStrength.BITS_192, 192),
            ("RSA", AlgorithmFamily.RSA, 15360, None, ClassicalSecurityStrength.BITS_256, 256),
            # ECC Curves
            ("ECDSA", AlgorithmFamily.EC, None, "secp224r1", ClassicalSecurityStrength.LEGACY_112, 112),
            ("ECDSA", AlgorithmFamily.EC, None, "secp256r1", ClassicalSecurityStrength.BITS_128, 128),
            ("ECDSA", AlgorithmFamily.EC, None, "secp384r1", ClassicalSecurityStrength.BITS_192, 192),
            ("ECDSA", AlgorithmFamily.EC, None, "secp521r1", ClassicalSecurityStrength.BITS_256, 256),
            # Symmetric
            ("AES", AlgorithmFamily.AES, 128, None, ClassicalSecurityStrength.BITS_128, 128),
            ("AES", AlgorithmFamily.AES, 192, None, ClassicalSecurityStrength.BITS_192, 192),
            ("AES", AlgorithmFamily.AES, 256, None, ClassicalSecurityStrength.BITS_256, 256),
            ("DES", AlgorithmFamily.DES, 56, None, ClassicalSecurityStrength.DISALLOWED_SUB_112, 56),
        ]

        for algo, fam, ksz, crv, expected_strength, expected_bits in test_cases:
            asset = self._create_mock_asset(algo_name=algo, family=fam, key_size=ksz, curve_name=crv)
            strength, bits, rat, cites = classify_classical_security_strength(asset)
            self.assertEqual(strength, expected_strength, f"Failed on {algo} ksz={ksz} crv={crv}: got {strength.value}")
            self.assertEqual(bits, expected_bits, f"Failed bits on {algo} ksz={ksz} crv={crv}: got {bits}")
            self.assertTrue(len(cites) > 0)

    # =========================================================================
    # 5. Agility Modeling Tests
    # =========================================================================

    def test_12_agility_hardcoded_literal_detected(self) -> None:
        """Verifies hardcoded string literals evaluate to AgilityLevel.HARDCODED."""
        asset = self._create_mock_asset(
            matched_text='Cipher.getInstance("RSA/ECB/PKCS1Padding");',
            code_snippet='Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");',
        )
        ag = assess_cryptographic_agility(asset)
        self.assertEqual(ag.level, AgilityLevel.HARDCODED)
        self.assertTrue(any("hardcoded string literal" in f for f in ag.evidenced_factors))

    def test_13_agility_configurable_retrieval_detected(self) -> None:
        """Verifies environmental/config retrieval evaluates to AgilityLevel.CONFIGURABLE."""
        asset = self._create_mock_asset(
            matched_text='Cipher.getInstance(System.getenv("CIPHER_ALGO"));',
            code_snippet='String algo = System.getenv("CIPHER_ALGO");\nCipher c = Cipher.getInstance(algo);',
        )
        ag = assess_cryptographic_agility(asset)
        self.assertEqual(ag.level, AgilityLevel.CONFIGURABLE)
        self.assertTrue(any("Configurable retrieval pattern" in f for f in ag.evidenced_factors))

    def test_14_agility_modular_wrapper_detected(self) -> None:
        """Verifies call site in wrapper/helper class is recognized."""
        asset = self._create_mock_asset(
            file_path="src/security/CryptoHelper.java",
            matched_text='return provider.getCipher(name);',
            code_snippet='public Cipher getCipher(String name) { return provider.getCipher(name); }',
        )
        ag = assess_cryptographic_agility(asset)
        self.assertEqual(ag.level, AgilityLevel.MODULAR_PROVIDER)
        self.assertTrue(any("abstraction/wrapper module" in f for f in ag.evidenced_factors))

    def test_15_agility_non_source_location_unevaluated(self) -> None:
        """Verifies non-source location yields AgilityLevel.UNEVALUATED without crashing."""
        asset = CryptoAsset(
            asset_id="pkg-01",
            asset_type=AssetType.LIBRARY_DEPENDENCY,
            algorithm_identity=AlgorithmIdentity(family=AlgorithmFamily.UNKNOWN, algorithm="bcprov"),
            role=CryptographicRole.UNKNOWN,
            parameters=AlgorithmParameters(),
            finding_ids=["f-01"],
            primary_location=EvidenceLocation(location_type=LocationType.DEPENDENCY, package_coordinate="pkg:maven/bcprov"),
            confidence=ConfidenceLevel.CONFIRMED,
            correlation_basis="test",
        )
        ag = assess_cryptographic_agility(asset)
        self.assertEqual(ag.level, AgilityLevel.UNEVALUATED)
        self.assertTrue(any("unobserved in static AST" in l for l in ag.limitations_and_unknowns))

    # =========================================================================
    # 6. Safety, Immutability, and Batch Processing Tests
    # =========================================================================

    def test_16_non_mutation_of_phase3_assets(self) -> None:
        """Verifies that running target mapper does NOT mutate any field of input CryptoAsset."""
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.KEY_GENERATION,
            key_size=2048,
        )
        orig_dict = asset.to_dict()
        res = self.mapper.map_asset(asset)

        # Asset state must remain identical
        self.assertEqual(asset.to_dict(), orig_dict)
        self.assertEqual(res.source_asset_id, asset.asset_id)

    def test_17_immutability_of_mapping_records(self) -> None:
        """Verifies that PqcTargetMapping and CandidateTarget are frozen against attribute mutation."""
        asset = self._create_mock_asset()
        res = self.mapper.map_asset(asset)

        with self.assertRaises((AttributeError, TypeError)):
            res.mapping_status = TargetMappingStatus.UNSUPPORTED  # type: ignore

        if res.candidate_targets:
            with self.assertRaises((AttributeError, TypeError)):
                res.candidate_targets[0].parameter_set = "HACKED"  # type: ignore

    def test_18_batch_mapping_deterministic_sorting(self) -> None:
        """Verifies batch mapping map_assets processes multiple assets deterministically sorted by asset_id."""
        a1 = self._create_mock_asset(asset_id="asset-z", algo_name="RSA", key_size=2048)
        a2 = self._create_mock_asset(asset_id="asset-a", algo_name="AES", family=AlgorithmFamily.AES, key_size=256)
        a3 = self._create_mock_asset(asset_id="asset-m", algo_name="ECDSA", family=AlgorithmFamily.EC, curve_name="secp256r1")

        batch = self.mapper.map_assets([a1, a2, a3])
        self.assertEqual(len(batch), 3)
        self.assertEqual([r.source_asset_id for r in batch], ["asset-a", "asset-m", "asset-z"])

    def test_19_invalid_asset_type_raises_type_error(self) -> None:
        """Verifies passing an invalid object raises TypeError."""
        with self.assertRaises(TypeError):
            self.mapper.map_asset("not_an_asset")  # type: ignore

    def test_20_unsupported_role_combination(self) -> None:
        """Verifies unsupported role combinations evaluate to UNSUPPORTED."""
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.MESSAGE_DIGEST,  # RSA cannot be a message digest
            key_size=2048,
        )
        res = self.mapper.map_asset(asset)
        self.assertEqual(res.mapping_status, TargetMappingStatus.UNSUPPORTED)
        self.assertEqual(len(res.candidate_targets), 0)
        self.assertTrue(res.required_human_review)

    # =========================================================================
    # 7. Semantic Boundaries: Classical Strength vs PQC Categories vs Candidates
    # =========================================================================

    def test_21_strict_separation_of_classical_strength_and_pqc_categories(self) -> None:
        """
        Verifies that classical security strength (in bits) is strictly decoupled from
        NIST PQC security categories. RSA-3072 must NOT be labeled with a PQC category.
        """
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.ENCRYPTION_DECRYPTION,
            key_size=3072,
        )
        res = self.mapper.map_asset(asset)

        # 1. Classical strength is 128 bits under NIST SP 800-57 Pt 1 Rev 5 Table 2
        self.assertEqual(res.classical_security_strength, ClassicalSecurityStrength.BITS_128)
        self.assertEqual(res.classical_bits, 128)

        # 2. Target equivalence category is Category 1 (minimum parity requirement)
        self.assertEqual(res.target_equivalence_category, PqcSecurityCategory.CATEGORY_1)

        # 3. Candidate targets themselves carry PQC Security Categories (FIPS 203)
        for t in res.candidate_targets:
            self.assertIsInstance(t.pqc_security_category, PqcSecurityCategory)
            self.assertIn(t.pqc_security_category, (PqcSecurityCategory.CATEGORY_1, PqcSecurityCategory.CATEGORY_3, PqcSecurityCategory.CATEGORY_5))

        # 4. Selection basis explicitly explains the rationale
        self.assertTrue(len(res.selection_basis) > 0)
        self.assertIn("112-128 bits classical security", res.selection_basis)

    def test_22_candidate_versus_approved_target_semantics(self) -> None:
        """
        Verifies that target mappings produce candidate proposals for evaluation,
        never claiming that a target is approved, drop-in, or compatibility-guaranteed.
        """
        asset = self._create_mock_asset(
            algo_name="ECDSA",
            family=AlgorithmFamily.EC,
            role=CryptographicRole.DIGITAL_SIGNATURE,
            curve_name="secp256r1",
        )
        res = self.mapper.map_asset(asset)

        # Ensure candidates are populated as non-binding options
        self.assertTrue(len(res.candidate_targets) >= 2)
        # Ensure compatibility considerations disclose signature expansion and fragmentation
        self.assertTrue(any("Signature size expansion" in c for c in res.compatibility_considerations))
        self.assertTrue(any("TLS handshake" in c for c in res.compatibility_considerations))
        # Ensure serialization contains explicit dictionary keys
        d = res.to_dict()
        self.assertIn("candidate_targets", d)
        self.assertIn("selection_basis", d)
        self.assertIn("compatibility_considerations", d)
        self.assertNotIn("approved_targets", d)

    def test_23_quantum_exposure_distinct_from_classical_disallowance(self) -> None:
        """
        Verifies that classical disallowance (< 112 bits) is distinct from quantum vulnerability.
        RSA-1024 is disallowed classically (< 112 bits). RSA-4096 is classically strong (~140 bits).
        Both are vulnerable to Shor's algorithm, but have distinct classical strengths.
        """
        asset_1024 = self._create_mock_asset(algo_name="RSA", key_size=1024)
        asset_4096 = self._create_mock_asset(algo_name="RSA", key_size=4096)

        res_1024 = self.mapper.map_asset(asset_1024)
        res_4096 = self.mapper.map_asset(asset_4096)

        self.assertEqual(res_1024.classical_security_strength, ClassicalSecurityStrength.DISALLOWED_SUB_112)
        self.assertEqual(res_4096.classical_security_strength, ClassicalSecurityStrength.BITS_128)
        self.assertEqual(res_4096.classical_bits, 140)

    def test_24_ecc_curve_parameter_boundaries(self) -> None:
        """Verifies boundary curves P-224 (legacy), P-256 (128-bit), P-384 (192-bit), P-521 (256-bit)."""
        curves = [
            ("secp224r1", ClassicalSecurityStrength.LEGACY_112, 112, PqcSecurityCategory.CATEGORY_1),
            ("secp256r1", ClassicalSecurityStrength.BITS_128, 128, PqcSecurityCategory.CATEGORY_1),
            ("secp384r1", ClassicalSecurityStrength.BITS_192, 192, PqcSecurityCategory.CATEGORY_3),
            ("secp521r1", ClassicalSecurityStrength.BITS_256, 256, PqcSecurityCategory.CATEGORY_5),
        ]
        for curve_name, exp_strength, exp_bits, exp_equiv in curves:
            asset = self._create_mock_asset(
                algo_name="ECDSA",
                family=AlgorithmFamily.EC,
                role=CryptographicRole.DIGITAL_SIGNATURE,
                curve_name=curve_name,
            )
            res = self.mapper.map_asset(asset)
            self.assertEqual(res.classical_security_strength, exp_strength)
            self.assertEqual(res.classical_bits, exp_bits)
            self.assertEqual(res.target_equivalence_category, exp_equiv)

    def test_25_unsupported_and_ambiguous_roles_fail_closed(self) -> None:
        """Verifies that an asset with an unknown role fails closed to CONDITIONAL / review."""
        asset = self._create_mock_asset(
            algo_name="RSA",
            family=AlgorithmFamily.RSA,
            role=CryptographicRole.UNKNOWN,
            key_size=2048,
        )
        res = self.mapper.map_asset(asset)
        self.assertEqual(res.mapping_status, TargetMappingStatus.CONDITIONAL)
        self.assertTrue(res.required_human_review)


if __name__ == "__main__":
    unittest.main()
