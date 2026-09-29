package tc05;

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * TC-05: Explicit Elliptic Curve Diffie-Hellman (ECDH) Key Agreement.
 * Purpose: Tests whether a discovery tool identifies ECDH protocol usage,
 * and correctly determines the operational role as KEY ESTABLISHMENT based
 * on JCA KeyAgreement API usage.
 */
public class EcdhKeyAgreement {

    private static final String AGREEMENT_ALGORITHM = "ECDH";

    public byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey peerPublicKey) throws GeneralSecurityException {
        // Line 20: Direct JCA KeyAgreement instantiation with algorithm "ECDH"
        KeyAgreement keyAgreement = KeyAgreement.getInstance(AGREEMENT_ALGORITHM);
        
        // Line 23: Key agreement initialization with local private key
        keyAgreement.init(privateKey);
        
        // Line 26: Key agreement execution with remote public key
        keyAgreement.doPhase(peerPublicKey, true);
        
        // Line 29: Shared secret generation
        return keyAgreement.generateSecret();
    }
}
