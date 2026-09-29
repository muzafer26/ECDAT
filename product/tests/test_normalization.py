"""
Tests for Normalization Invariants and Specificity Rules.
"""

import unittest

from product.core.evidence.evidence import EvidenceRecord, SourceLocation, DetectionMethod
from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.role import CryptographicRole
from product.core.domain.confidence import ConfidenceLevel, DispositionStatus
from product.core.domain.observation import ObservationType
from product.core.normalization.normalizer import NormalizationEngine


class TestNormalization(unittest.TestCase):

    def setUp(self) -> None:
        self.normalizer = NormalizationEngine()

    def test_evidence_is_never_mutated_or_deleted_during_normalization(self) -> None:
        """Verifies evidence record fields remain completely unmodified after normalization."""
        ev = EvidenceRecord(
            evidence_id="ev-orig",
            location=SourceLocation(file_path="src/App.java", line_start=5, line_end=5, matched_text="Cipher.getInstance(\"AES\")"),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="CERT-SYM-001",
            scanner_confidence="HIGH",
        )

        orig_category = ev.scanner_category
        orig_method = ev.detection_method

        finding = self.normalizer.normalize(ev)

        # Evidence fields remain intact
        self.assertEqual(ev.scanner_category, orig_category)
        self.assertEqual(ev.detection_method, orig_method)
        # Finding points back to evidence
        self.assertIn(ev.evidence_id, finding.evidence_ids)

    def test_specificity_invariant_generic_ecc_remains_unknown(self) -> None:
        """Verifies generic ECC keygen is NOT elevated to ECDSA or ECDH without evidence."""
        ev = EvidenceRecord(
            evidence_id="ev-ec-generic",
            location=SourceLocation(
                file_path="src/KeyGen.java",
                line_start=12,
                line_end=12,
                matched_text="KeyPairGenerator.getInstance(\"EC\");",
                code_snippet="KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"EC\");\nkpg.initialize(new ECGenParameterSpec(\"secp256r1\"));",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="ECC",
        )

        finding = self.normalizer.normalize(ev)

        # Specificity invariant: family is EC, but algorithm remains UNKNOWN
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.EC)
        self.assertEqual(finding.algorithm_identity.algorithm, "UNKNOWN")
        self.assertEqual(finding.algorithm_identity.variant, "secp256r1")
        self.assertEqual(finding.role, CryptographicRole.KEY_GENERATION)

    def test_ecc_evidence_alone_is_not_ecdh_interpretation(self) -> None:
        """Verifies: ECC evidence alone != ECDH interpretation."""
        ev_ecc_only = EvidenceRecord(
            evidence_id="ev-ecc-only",
            location=SourceLocation(
                file_path="src/Token.java",
                line_start=20,
                line_end=20,
                matched_text="// Using ECC keys for tokens",
                code_snippet="// Using ECC keys for tokens",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.COMMENT_MATCH,
            scanner_category="ECC",
        )

        finding = self.normalizer.normalize(ev_ecc_only)
        self.assertNotEqual(finding.algorithm_identity.algorithm, "ECDH")
        self.assertEqual(finding.algorithm_identity.algorithm, "UNKNOWN")

    def test_ecdh_is_interpreted_only_with_specific_evidence(self) -> None:
        """Verifies ECDH is interpreted when KeyAgreement API or ECDH token is evidenced."""
        ev_ecdh = EvidenceRecord(
            evidence_id="ev-ecdh",
            location=SourceLocation(
                file_path="src/Agreement.java",
                line_start=30,
                line_end=30,
                matched_text="KeyAgreement.getInstance(\"ECDH\");",
                code_snippet="KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\");\nka.init(privateKey);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="ECC",  # Scanner reports generic ECC
        )

        finding = self.normalizer.normalize(ev_ecdh)

        # Scanner category preserved in evidence
        self.assertEqual(ev_ecdh.scanner_category, "ECC")
        # ECDAT interprets as ECDH because KeyAgreement.getInstance("ECDH") is evidenced
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.EC)
        self.assertEqual(finding.algorithm_identity.algorithm, "ECDH")
        self.assertEqual(finding.role, CryptographicRole.KEY_AGREEMENT)

    def test_scanner_category_preserved_when_misclassified(self) -> None:
        """Verifies raw scanner category is retained even when ECDAT assigns correct role."""
        ev_ecdsa_misclass = EvidenceRecord(
            evidence_id="ev-ecdsa",
            location=SourceLocation(
                file_path="src/Signer.java",
                line_start=45,
                line_end=45,
                matched_text="Signature.getInstance(\"SHA256withECDSA\");",
                code_snippet="Signature sig = Signature.getInstance(\"SHA256withECDSA\");\nsig.initSign(privKey);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="CERT-SIGALG-001",  # Scanner misclassified rule category
        )

        finding = self.normalizer.normalize(ev_ecdsa_misclass)

        # Evidence category untouched
        self.assertEqual(ev_ecdsa_misclass.scanner_category, "CERT-SIGALG-001")
        # ECDAT domain interpretation
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.EC)
        self.assertEqual(finding.algorithm_identity.algorithm, "ECDSA")
        self.assertEqual(finding.role, CryptographicRole.DIGITAL_SIGNATURE)

    def test_dynamic_cipher_remains_unknown_needs_review(self) -> None:
        """Verifies dynamic runtime cipher string resolution remains UNKNOWN (no invented AES)."""
        ev_dynamic = EvidenceRecord(
            evidence_id="ev-dyn",
            location=SourceLocation(
                file_path="src/DynamicService.java",
                line_start=18,
                line_end=18,
                matched_text="Cipher.getInstance(System.getenv(\"APP_CIPHER\"))",
                code_snippet="String algo = System.getenv(\"APP_CIPHER\");\nCipher c = Cipher.getInstance(algo);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="CIPHER",
        )

        finding = self.normalizer.normalize(ev_dynamic)

        self.assertEqual(finding.observation_type, ObservationType.AMBIGUOUS_CALL)
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.UNKNOWN)
        self.assertEqual(finding.algorithm_identity.algorithm, "UNKNOWN")
        self.assertEqual(finding.role, CryptographicRole.ENCRYPTION_DECRYPTION)
        self.assertEqual(finding.confidence, ConfidenceLevel.NEEDS_REVIEW)
        self.assertEqual(finding.disposition, DispositionStatus.NEEDS_REVIEW)

    def test_comment_only_matches_preserve_evidence_with_false_positive_disposition(self) -> None:
        """Verifies comment matches are NOT deleted, but classified as COMMENT_ONLY / FALSE_POSITIVE."""
        ev_comment = EvidenceRecord(
            evidence_id="ev-comm",
            location=SourceLocation(
                file_path="src/Decoy.java",
                line_start=5,
                line_end=5,
                matched_text="// TODO: migrate away from RSA to PQC later",
                code_snippet="// TODO: migrate away from RSA to PQC later",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.COMMENT_MATCH,
            scanner_category="RSA",
        )

        finding = self.normalizer.normalize(ev_comment)

        self.assertEqual(finding.observation_type, ObservationType.COMMENT_ONLY)
        self.assertEqual(finding.disposition, DispositionStatus.FALSE_POSITIVE)
        self.assertEqual(finding.confidence, ConfidenceLevel.NEEDS_REVIEW)
        self.assertIn(ev_comment.evidence_id, finding.evidence_ids)

    def test_dependency_declaration_does_not_infer_algorithm(self) -> None:
        """Verifies lockfile/manifest package is LIBRARY_DEPENDENCY with UNKNOWN algorithm."""
        ev_dep = EvidenceRecord(
            evidence_id="ev-dep",
            location=SourceLocation(
                file_path="pom.xml",
                line_start=25,
                line_end=28,
                matched_text="<artifactId>bcprov-jdk18on</artifactId>",
                code_snippet="<dependency>\n  <groupId>org.bouncycastle</groupId>\n  <artifactId>bcprov-jdk18on</artifactId>\n  <version>1.78.1</version>\n</dependency>",
            ),
            scanner_name="Syft",
            scanner_version="1.51.1",
            detection_method=DetectionMethod.LOCKFILE_PARSE,
            scanner_category="java-archive",
        )

        finding = self.normalizer.normalize(ev_dep)

        self.assertEqual(finding.observation_type, ObservationType.LIBRARY_DEPENDENCY)
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.UNKNOWN)
        self.assertEqual(finding.algorithm_identity.algorithm, "UNKNOWN")
        self.assertEqual(finding.role, CryptographicRole.UNKNOWN)

    def test_h03_dh_code_with_ecc_scanner_category_does_not_become_ecdh(self) -> None:
        """H-03: Verifies KeyAgreement.getInstance('DH') with scanner category 'ECC' NEVER becomes ECDH."""
        ev = EvidenceRecord(
            evidence_id="ev-dh-ecc-cat",
            location=SourceLocation(
                file_path="src/DhAgreement.java",
                line_start=15,
                line_end=15,
                matched_text="KeyAgreement ka = KeyAgreement.getInstance(\"DH\");",
                code_snippet="KeyAgreement ka = KeyAgreement.getInstance(\"DH\");\nka.init(keyPair.getPrivate());",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="ECC",  # Generic/incorrect scanner category
        )
        finding = self.normalizer.normalize(ev)

        # Invariant: EVIDENCE >= INTERPRETATION. Scanner category must not manufacture ECDH.
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.DH)
        self.assertEqual(finding.algorithm_identity.algorithm, "DH")
        self.assertNotEqual(finding.algorithm_identity.algorithm, "ECDH")
        self.assertEqual(finding.role, CryptographicRole.KEY_AGREEMENT)
        self.assertEqual(finding.confidence, ConfidenceLevel.CONFIRMED)
        self.assertEqual(ev.scanner_category, "ECC")  # Raw evidence preserved unmodified

    def test_h03_dh_code_with_ec_scanner_category_does_not_become_ecdh(self) -> None:
        """H-03: Verifies KeyAgreement.getInstance('DH') with scanner category 'EC' NEVER becomes ECDH."""
        ev = EvidenceRecord(
            evidence_id="ev-dh-ec-cat",
            location=SourceLocation(
                file_path="src/DhAgreement.java",
                line_start=22,
                line_end=22,
                matched_text="KeyAgreement ka = KeyAgreement.getInstance(\"DH\");",
                code_snippet="KeyAgreement ka = KeyAgreement.getInstance(\"DH\");",
            ),
            scanner_name="ScannerX",
            scanner_version="2.0.0",
            detection_method=DetectionMethod.SEMANTIC_REGEX,
            scanner_category="EC",
        )
        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.DH)
        self.assertEqual(finding.algorithm_identity.algorithm, "DH")
        self.assertNotEqual(finding.algorithm_identity.algorithm, "ECDH")
        self.assertEqual(finding.role, CryptographicRole.KEY_AGREEMENT)

    def test_h03_generic_keyagreement_with_ecc_scanner_category_does_not_become_ecdh(self) -> None:
        """H-03: Verifies generic KeyAgreement with scanner category 'ECC' remains UNKNOWN algorithm."""
        ev = EvidenceRecord(
            evidence_id="ev-generic-ka",
            location=SourceLocation(
                file_path="src/GenericAgreement.java",
                line_start=35,
                line_end=35,
                matched_text="KeyAgreement ka = KeyAgreement.getInstance(algoParam);",
                code_snippet="KeyAgreement ka = KeyAgreement.getInstance(algoParam);\nka.init(priv);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="ECC",
        )
        finding = self.normalizer.normalize(ev)

        # Specificity Invariant: Generic scanner category cannot invent specific ECDH algorithm
        self.assertEqual(finding.algorithm_identity.algorithm, "UNKNOWN")
        self.assertNotEqual(finding.algorithm_identity.algorithm, "ECDH")
        self.assertEqual(finding.role, CryptographicRole.KEY_AGREEMENT)
        self.assertEqual(finding.confidence, ConfidenceLevel.NEEDS_REVIEW)

    def test_h03_explicit_ecdh_code_normalizes_to_ecdh(self) -> None:
        """H-03: Verifies explicit ECDH in code correctly normalizes to ECDH."""
        ev = EvidenceRecord(
            evidence_id="ev-explicit-ecdh",
            location=SourceLocation(
                file_path="src/EcdhAgreement.java",
                line_start=40,
                line_end=40,
                matched_text="KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\");",
                code_snippet="KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\");",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="CRYPTO",
        )
        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.EC)
        self.assertEqual(finding.algorithm_identity.algorithm, "ECDH")
        self.assertEqual(finding.role, CryptographicRole.KEY_AGREEMENT)
        self.assertEqual(finding.confidence, ConfidenceLevel.CONFIRMED)

    def test_h03_dynamic_unknown_keyagreement_remains_unknown(self) -> None:
        """H-03: Verifies dynamic KeyAgreement call remains UNKNOWN with NEEDS_REVIEW."""
        ev = EvidenceRecord(
            evidence_id="ev-dyn-ka",
            location=SourceLocation(
                file_path="src/DynamicAgreement.java",
                line_start=50,
                line_end=50,
                matched_text="KeyAgreement ka = KeyAgreement.getInstance(System.getenv(\"KA_ALGO\"));",
                code_snippet="KeyAgreement ka = KeyAgreement.getInstance(System.getenv(\"KA_ALGO\"));",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="KEY_EXCHANGE",
        )
        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.algorithm_identity.algorithm, "UNKNOWN")
        self.assertEqual(finding.confidence, ConfidenceLevel.NEEDS_REVIEW)
        self.assertEqual(finding.disposition, DispositionStatus.NEEDS_REVIEW)


if __name__ == "__main__":
    unittest.main()

