package tc11;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

/**
 * TC-11: Ambiguous & Dynamic Cryptographic Invocation (AMBIGUOUS CASE).
 * Purpose: Tests whether discovery engines safely preserve uncertainty when the
 * cryptographic transformation string cannot be statically determined at compile time.
 * The algorithm is supplied via an environment variable or system property.
 */
public class DynamicCipherService {

    public byte[] processDataWithDynamicCipher(byte[] payload, SecretKey key) throws GeneralSecurityException {
        // Line 16: Algorithm string loaded dynamically from runtime environment
        String configuredTransformation = System.getenv("DYNAMIC_CIPHER_TRANSFORMATION");
        
        if (configuredTransformation == null || configuredTransformation.isEmpty()) {
            configuredTransformation = System.getProperty("app.crypto.default", "UNKNOWN_ALGO");
        }

        // Line 23: Dynamic Cipher instantiation where transformation is an unresolved variable
        Cipher cipher = Cipher.getInstance(configuredTransformation);
        
        // Line 26: Initialization and execution
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(payload);
    }
}
