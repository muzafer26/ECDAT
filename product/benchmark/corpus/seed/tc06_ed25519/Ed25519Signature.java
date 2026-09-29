package tc06;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * TC-06: Modern Edwards-Curve Digital Signature Algorithm (Ed25519).
 * Purpose: Tests whether a discovery tool recognizes modern Curve25519-based
 * signature schemes (Ed25519) and correctly identifies the operational role
 * as DIGITAL SIGNATURE.
 */
public class Ed25519Signature {

    private static final String ALGORITHM = "Ed25519";

    public byte[] signPayload(byte[] message, PrivateKey privateKey) throws GeneralSecurityException {
        // Line 19: Direct JCA Signature instantiation with algorithm "Ed25519"
        Signature signature = Signature.getInstance(ALGORITHM);
        
        // Line 22: Signature initialization for signing
        signature.initSign(privateKey);
        
        // Line 25: Update signature engine with message bytes
        signature.update(message);
        
        // Line 28: Generate digital signature
        return signature.sign();
    }
}
