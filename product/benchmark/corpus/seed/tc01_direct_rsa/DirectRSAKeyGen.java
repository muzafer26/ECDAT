package tc01;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * TC-01: Direct RSA Key Pair Generation.
 * Purpose: Tests whether a discovery tool identifies direct RSA algorithm instantiation
 * and extracts the configured key size (2048 bits).
 */
public class DirectRSAKeyGen {

    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        // Line 16: Direct JCA KeyPairGenerator instantiation with algorithm "RSA"
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        
        // Line 19: Key size initialization with 2048 bits
        keyGen.initialize(2048);
        
        // Line 22: Key pair generation
        return keyGen.generateKeyPair();
    }
}
