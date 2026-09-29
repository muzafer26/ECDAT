package tc04;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * TC-04: Explicit Elliptic Curve Digital Signature Algorithm (ECDSA).
 * Purpose: Tests whether a discovery tool identifies ECDSA signature usage,
 * associates the SHA-256 digest algorithm, and correctly determines the
 * operational role as DIGITAL SIGNATURE based on Signature API usage.
 */
public class EcdsaSignature {

    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

    public byte[] signData(byte[] payload, PrivateKey privateKey) throws GeneralSecurityException {
        // Line 19: Direct JCA Signature instantiation with algorithm "SHA256withECDSA"
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        
        // Line 22: Signature initialization for signing with private key
        signature.initSign(privateKey);
        
        // Line 25: Data update for signature computation
        signature.update(payload);
        
        // Line 28: Digital signature generation
        return signature.sign();
    }
}
