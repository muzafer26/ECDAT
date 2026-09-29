"""
Tests for ECDAT Canonical Domain Models.
"""

import unittest

from product.core.domain.confidence import ConfidenceLevel, DispositionStatus
from product.core.domain.observation import ObservationType
from product.core.domain.role import CryptographicRole
from product.core.domain.parameters import AlgorithmParameters
from product.core.domain.algorithm import AlgorithmFamily, AlgorithmIdentity


class TestDomainModels(unittest.TestCase):

    def test_confidence_level_does_not_contain_false_positive_if_detected(self) -> None:
        """Verifies FALSE_POSITIVE_IF_DETECTED is strictly excluded from ConfidenceLevel."""
        values = [m.value for m in ConfidenceLevel]
        self.assertNotIn("FALSE_POSITIVE_IF_DETECTED", values)
        self.assertIn("CONFIRMED", values)
        self.assertIn("LIKELY", values)
        self.assertIn("POSSIBLE", values)
        self.assertIn("NEEDS_REVIEW", values)
        self.assertIn("UNKNOWN", values)

    def test_disposition_status_values(self) -> None:
        """Verifies review disposition states."""
        values = [m.value for m in DispositionStatus]
        self.assertIn("UNREVIEWED", values)
        self.assertIn("CONFIRMED", values)
        self.assertIn("FALSE_POSITIVE", values)
        self.assertIn("SUPPRESSED", values)
        self.assertIn("NEEDS_REVIEW", values)

    def test_role_does_not_contain_none_decoy(self) -> None:
        """Verifies NONE_DECOY is strictly excluded from CryptographicRole."""
        values = [m.value for m in CryptographicRole]
        self.assertNotIn("none_decoy", values)
        self.assertNotIn("NONE_DECOY", values)
        # Genuine roles are present
        self.assertIn("encryption_decryption", values)
        self.assertIn("digital_signature", values)
        self.assertIn("key_agreement", values)
        self.assertIn("key_generation", values)
        self.assertIn("message_digest", values)

    def test_decoys_are_modeled_as_observation_types(self) -> None:
        """Verifies decoys and comments are observations."""
        values = [m.value for m in ObservationType]
        self.assertIn("comment_only", values)
        self.assertIn("non_cryptographic_decoy", values)
        self.assertIn("cryptographic_usage", values)
        self.assertIn("library_dependency", values)
        self.assertIn("ambiguous_call", values)

    def test_algorithm_identity_does_not_collapse_ecc(self) -> None:
        """Verifies that ECDSA, ECDH, and Ed25519 remain distinct and are not collapsed."""
        ecdsa = AlgorithmIdentity(family=AlgorithmFamily.EC, algorithm="ECDSA", variant="secp256r1")
        ecdh = AlgorithmIdentity(family=AlgorithmFamily.EC, algorithm="ECDH")
        ed25519 = AlgorithmIdentity(family=AlgorithmFamily.EDWARDS, algorithm="Ed25519")
        generic_ec = AlgorithmIdentity(family=AlgorithmFamily.EC, algorithm="UNKNOWN")

        self.assertEqual(ecdsa.algorithm, "ECDSA")
        self.assertEqual(ecdh.algorithm, "ECDH")
        self.assertEqual(ed25519.algorithm, "Ed25519")
        self.assertEqual(generic_ec.algorithm, "UNKNOWN")

        self.assertNotEqual(ecdsa.algorithm, ecdh.algorithm)
        self.assertNotEqual(ecdsa.algorithm, ed25519.algorithm)
        self.assertNotEqual(ecdsa.algorithm, generic_ec.algorithm)

    def test_parameters_integrity(self) -> None:
        """Verifies parameter typing and DES effective strength distinction."""
        params = AlgorithmParameters(
            key_size_bits=2048,
            cipher_mode="GCM",
            padding_scheme="NoPadding",
            curve_name="secp256r1",
            effective_key_bits=56,
        )
        self.assertEqual(params.key_size_bits, 2048)
        self.assertEqual(params.effective_key_bits, 56)

        d = params.to_dict()
        restored = AlgorithmParameters.from_dict(d)
        self.assertEqual(restored.key_size_bits, 2048)
        self.assertEqual(restored.effective_key_bits, 56)
        self.assertEqual(restored.cipher_mode, "GCM")


if __name__ == "__main__":
    unittest.main()
