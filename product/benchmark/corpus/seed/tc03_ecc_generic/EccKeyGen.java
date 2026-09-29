package tc03;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

/**
 * TC-03: Generic Elliptic Curve (ECC) Key Pair Generation.
 * Purpose: Tests whether a discovery tool identifies ECC key generation and the named curve
 * parameter ("secp256r1"), while properly leaving operational role as UNKNOWN since a raw
 * key pair generator does not define whether keys will be used for signatures or key agreement.
 */
public class EccKeyGen {

    public KeyPair generateECKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // Line 18: Direct JCA KeyPairGenerator instantiation with algorithm "EC"
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        
        // Line 21: Named curve parameter specification "secp256r1" (NIST P-256)
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(ecSpec);
        
        // Line 25: Key pair generation
        return keyGen.generateKeyPair();
    }
}
