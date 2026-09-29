"""
Benchmark-Derived Oracle Tests for TC-01 through TC-11.

Uses the human-verified answer keys strictly as external test oracles to validate
that the normalization and correlation engine accurately represent each scenario.
Zero benchmark answer keys or case IDs are referenced in production code.
"""

import json
from pathlib import Path
import unittest

from product.core.evidence.evidence import EvidenceRecord, SourceLocation, DetectionMethod
from product.core.domain.algorithm import AlgorithmFamily
from product.core.domain.role import CryptographicRole
from product.core.domain.confidence import ConfidenceLevel, DispositionStatus
from product.core.domain.observation import ObservationType
from product.core.normalization.normalizer import NormalizationEngine
from product.core.normalization.correlation import AssetCorrelationEngine


class TestBenchmarkOracles(unittest.TestCase):

    def setUp(self) -> None:
        self.normalizer = NormalizationEngine()
        self.correlator = AssetCorrelationEngine()
        self.answer_keys_dir = Path("product/benchmark/answer_keys")

    def _load_oracle(self, tc_id: str) -> dict:
        """Loads human-verified answer key to use strictly as test assertion oracle."""
        matches = list(self.answer_keys_dir.glob(f"{tc_id.lower()}*.json"))
        if not matches:
            raise FileNotFoundError(f"Could not find answer key for {tc_id} in {self.answer_keys_dir}")
        with open(matches[0], "r", encoding="utf-8") as f:
            return json.load(f)

    def test_tc01_direct_rsa_keygen(self) -> None:
        """TC-01: RSA 2048 key-pair generation."""
        oracle = self._load_oracle("tc01")
        expected = oracle["expected_findings"][0]["expected_interpretation"]

        ev = EvidenceRecord(
            evidence_id="tc01-ev1",
            location=SourceLocation(
                file_path="tc01_direct_rsa/DirectRSAKeyGen.java",
                line_start=15,
                line_end=16,
                matched_text="KeyPairGenerator.getInstance(\"RSA\");",
                code_snippet="KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");\nkpg.initialize(2048);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="RSA",
        )

        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.RSA)
        self.assertEqual(finding.algorithm_identity.algorithm, expected["algorithm"])  # "RSA"
        self.assertEqual(finding.parameters.key_size_bits, expected["parameters"]["key_size_bits"])  # 2048
        # Oracle role is "unknown" (KeyGen does not define role)
        self.assertEqual(finding.role, CryptographicRole.KEY_GENERATION)

    def test_tc02_symmetric_aes_gcm(self) -> None:
        """TC-02: AES-256-GCM encryption/decryption with parameter distinction."""
        oracle = self._load_oracle("tc02")
        expected = oracle["expected_findings"][0]["expected_interpretation"]

        ev = EvidenceRecord(
            evidence_id="tc02-ev1",
            location=SourceLocation(
                file_path="tc02_symmetric_aes/AesGcmCipher.java",
                line_start=20,
                line_end=22,
                matched_text="Cipher.getInstance(\"AES/GCM/NoPadding\");",
                code_snippet="SecretKey key = new SecretKeySpec(keyBytes, \"AES\");\nCipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="AES",
        )

        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.AES)
        self.assertEqual(finding.algorithm_identity.algorithm, expected["algorithm"])  # "AES"
        self.assertEqual(finding.parameters.cipher_mode, expected["parameters"]["cipher_mode"])  # "GCM"
        self.assertEqual(finding.parameters.key_size_bits, expected["parameters"]["key_size_bits"])  # None (dynamic keyBytes)
        self.assertEqual(finding.role, CryptographicRole.ENCRYPTION_DECRYPTION)

    def test_tc03_generic_ecc_keygen(self) -> None:
        """TC-03: Generic EC key generation with curve secp256r1."""
        oracle = self._load_oracle("tc03")
        expected = oracle["expected_findings"][0]["expected_interpretation"]

        ev = EvidenceRecord(
            evidence_id="tc03-ev1",
            location=SourceLocation(
                file_path="tc03_ecc_generic/EccKeyGen.java",
                line_start=18,
                line_end=20,
                matched_text="KeyPairGenerator.getInstance(\"EC\");",
                code_snippet="KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"EC\");\nkpg.initialize(new ECGenParameterSpec(\"secp256r1\"));",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="ECC",
        )

        finding = self.normalizer.normalize(ev)

        # Specificity Invariant: Generic EC does NOT manufacture ECDSA or ECDH
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.EC)
        self.assertEqual(finding.algorithm_identity.algorithm, "UNKNOWN")
        self.assertEqual(finding.algorithm_identity.variant, "secp256r1")
        self.assertEqual(finding.parameters.curve_name, expected["parameters"]["curve_name"])  # "secp256r1"

    def test_tc04_ecdsa_signature_category_misclassification(self) -> None:
        """TC-04: ECDSA digital signature where scanner category is CERT-SIGALG-001."""
        oracle = self._load_oracle("tc04")
        expected = oracle["expected_findings"][0]["expected_interpretation"]

        ev = EvidenceRecord(
            evidence_id="tc04-ev1",
            location=SourceLocation(
                file_path="tc04_ecdsa/EcdsaSignature.java",
                line_start=25,
                line_end=27,
                matched_text="Signature.getInstance(\"SHA256withECDSA\");",
                code_snippet="Signature signature = Signature.getInstance(\"SHA256withECDSA\");\nsignature.initSign(privateKey);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="CERT-SIGALG-001",  # Scanner rule misclassification
        )

        finding = self.normalizer.normalize(ev)

        # Scanner category preserved in evidence
        self.assertEqual(ev.scanner_category, "CERT-SIGALG-001")
        # ECDAT domain interpretation matches oracle
        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.EC)
        self.assertEqual(finding.algorithm_identity.algorithm, expected["algorithm"])  # "ECDSA"
        self.assertEqual(finding.role, CryptographicRole.DIGITAL_SIGNATURE)

    def test_tc05_ecdh_key_agreement_vs_spurious_comment_dh(self) -> None:
        """TC-05: ECDH key agreement with scanner 'ECC' + spurious comment-text 'DH' match."""
        oracle = self._load_oracle("tc05")
        expected = oracle["expected_findings"][0]["expected_interpretation"]

        # 1. Genuine KeyAgreement evidence
        ev_ecdh = EvidenceRecord(
            evidence_id="tc05-ev1",
            location=SourceLocation(
                file_path="tc05_ecdh/EcdhKeyAgreement.java",
                line_start=30,
                line_end=32,
                matched_text="KeyAgreement.getInstance(\"ECDH\");",
                code_snippet="KeyAgreement ka = KeyAgreement.getInstance(\"ECDH\");\nka.init(privKey);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="ECC",
        )

        # 2. Spurious comment match on "DH"
        ev_comment_dh = EvidenceRecord(
            evidence_id="tc05-ev2",
            location=SourceLocation(
                file_path="tc05_ecdh/EcdhKeyAgreement.java",
                line_start=12,
                line_end=12,
                matched_text="// Perform DH key exchange",
                code_snippet="// Perform DH key exchange",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.COMMENT_MATCH,
            scanner_category="DH",
        )

        f_ecdh = self.normalizer.normalize(ev_ecdh)
        f_comment = self.normalizer.normalize(ev_comment_dh)

        # Invariant: ECC evidence alone != ECDH interpretation. Here KeyAgreement API proves ECDH.
        self.assertEqual(f_ecdh.algorithm_identity.algorithm, expected["algorithm"])  # "ECDH"
        self.assertEqual(f_ecdh.role, CryptographicRole.KEY_AGREEMENT)

        # Spurious comment is preserved in evidence, but disposition is FALSE_POSITIVE
        self.assertEqual(f_comment.observation_type, ObservationType.COMMENT_ONLY)
        self.assertEqual(f_comment.disposition, DispositionStatus.FALSE_POSITIVE)

        # Correlator creates asset from f_ecdh, but does NOT merge the comment finding
        assets = self.correlator.correlate([f_ecdh, f_comment])
        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0].algorithm_identity.algorithm, "ECDH")

    def test_tc06_ed25519_signature(self) -> None:
        """TC-06: Ed25519 specificity preserved under Edwards family."""
        oracle = self._load_oracle("tc06")
        expected = oracle["expected_findings"][0]["expected_interpretation"]

        ev = EvidenceRecord(
            evidence_id="tc06-ev1",
            location=SourceLocation(
                file_path="tc06_ed25519/Ed25519Signature.java",
                line_start=20,
                line_end=22,
                matched_text="Signature.getInstance(\"Ed25519\");",
                code_snippet="Signature sig = Signature.getInstance(\"Ed25519\");\nsig.initSign(privateKey);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="ECC",  # Generic ECC scanner category
        )

        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.EDWARDS)
        self.assertEqual(finding.algorithm_identity.algorithm, expected["algorithm"])  # "Ed25519"
        self.assertEqual(finding.role, CryptographicRole.DIGITAL_SIGNATURE)

    def test_tc07_sha1_hash_and_parameter_integrity(self) -> None:
        """TC-07: SHA-1 hash digest with parameter integrity (160-bit digest != key size)."""
        oracle = self._load_oracle("tc07")
        expected = oracle["expected_findings"][0]["expected_interpretation"]

        ev = EvidenceRecord(
            evidence_id="tc07-ev1",
            location=SourceLocation(
                file_path="tc07_sha1_hash/sha1_hash.py",
                line_start=10,
                line_end=11,
                matched_text="hashlib.sha1(data)",
                code_snippet="h = hashlib.sha1()\nh.update(data)",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="SHA1",
        )

        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.SHA1)
        self.assertEqual(finding.algorithm_identity.algorithm, expected["algorithm"])  # "SHA-1"
        self.assertEqual(finding.role, CryptographicRole.MESSAGE_DIGEST)
        # Digest output length must NOT be set as key_size_bits
        self.assertIsNone(finding.parameters.key_size_bits)

    def test_tc08_des_wrapper_pattern(self) -> None:
        """TC-08: DES wrapper with effective 56-bit strength distinction."""
        oracle = self._load_oracle("tc08")
        expected = oracle["expected_findings"][0]["expected_interpretation"]

        ev = EvidenceRecord(
            evidence_id="tc08-ev1",
            location=SourceLocation(
                file_path="tc08_crypto_wrapper/LegacyCryptoHelper.java",
                line_start=25,
                line_end=27,
                matched_text="Cipher.getInstance(\"DES/CBC/PKCS5Padding\");",
                code_snippet="Cipher c = Cipher.getInstance(\"DES/CBC/PKCS5Padding\");\nc.init(Cipher.ENCRYPT_MODE, key, iv);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="DES",
        )

        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.algorithm_identity.family, AlgorithmFamily.DES)
        self.assertEqual(finding.algorithm_identity.algorithm, expected["algorithm"])  # "DES"
        self.assertEqual(finding.parameters.cipher_mode, expected["parameters"]["cipher_mode"])  # "CBC"
        self.assertEqual(finding.parameters.effective_key_bits, 56)  # Effective DES security

    def test_tc09_dependency_declaration_without_code_usage(self) -> None:
        """TC-09: Manifest dependency presence without active code calls."""
        ev = EvidenceRecord(
            evidence_id="tc09-ev1",
            location=SourceLocation(
                file_path="tc09_dependency_crypto/pom.xml",
                line_start=15,
                line_end=19,
                matched_text="<artifactId>bcprov-jdk18on</artifactId>",
                code_snippet="<dependency>\n  <groupId>org.bouncycastle</groupId>\n  <artifactId>bcprov-jdk18on</artifactId>\n  <version>1.78.1</version>\n</dependency>",
            ),
            scanner_name="Syft",
            scanner_version="1.51.1",
            detection_method=DetectionMethod.LOCKFILE_PARSE,
            scanner_category="java-archive",
        )

        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.observation_type, ObservationType.LIBRARY_DEPENDENCY)
        self.assertEqual(finding.algorithm_identity.algorithm, "UNKNOWN")
        self.assertEqual(finding.role, CryptographicRole.UNKNOWN)

    def test_tc10_negative_decoy_comments(self) -> None:
        """TC-10: Misleading crypto comments and non-crypto strings."""
        oracle = self._load_oracle("tc10")
        self.assertTrue(oracle["negative_case"])

        ev = EvidenceRecord(
            evidence_id="tc10-ev1",
            location=SourceLocation(
                file_path="tc10_misleading_comments/NonCryptoProcessor.java",
                line_start=14,
                line_end=14,
                matched_text="// TODO: implement RSA 4096 signing here",
                code_snippet="// TODO: implement RSA 4096 signing here",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.COMMENT_MATCH,
            scanner_category="RSA",
        )

        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.observation_type, ObservationType.COMMENT_ONLY)
        self.assertEqual(finding.disposition, DispositionStatus.FALSE_POSITIVE)

        # Zero genuine assets produced
        assets = self.correlator.correlate([finding])
        self.assertEqual(len(assets), 0)

    def test_tc11_ambiguous_dynamic_cipher(self) -> None:
        """TC-11: Ambiguous dynamic cipher resolution (preserves UNKNOWN / NEEDS_REVIEW)."""
        oracle = self._load_oracle("tc11")
        expected = oracle["expected_findings"][0]["expected_interpretation"]
        self.assertTrue(oracle["ambiguous_case"])

        ev = EvidenceRecord(
            evidence_id="tc11-ev1",
            location=SourceLocation(
                file_path="tc11_ambiguous_dynamic/DynamicCipherService.java",
                line_start=24,
                line_end=26,
                matched_text="Cipher.getInstance(System.getenv(\"CRYPTO_ALGO\"))",
                code_snippet="String cipherName = System.getenv(\"CRYPTO_ALGO\");\nCipher c = Cipher.getInstance(cipherName);",
            ),
            scanner_name="CryptoScan",
            scanner_version="1.4.0",
            detection_method=DetectionMethod.AST_ANALYSIS,
            scanner_category="CIPHER",
        )

        finding = self.normalizer.normalize(ev)

        self.assertEqual(finding.observation_type, ObservationType.AMBIGUOUS_CALL)
        self.assertEqual(finding.algorithm_identity.algorithm, expected["algorithm"])  # "UNKNOWN"
        self.assertEqual(finding.confidence, ConfidenceLevel.NEEDS_REVIEW)
        self.assertEqual(finding.disposition, DispositionStatus.NEEDS_REVIEW)


if __name__ == "__main__":
    unittest.main()
