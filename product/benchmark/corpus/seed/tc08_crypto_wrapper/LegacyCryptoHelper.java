package tc08;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * TC-08 Helper Component: Internal Cryptographic Utility Class.
 * Purpose: Encapsulates legacy DES cipher invocation inside a helper method.
 * Contains the direct API call site at line 23.
 */
public class LegacyCryptoHelper {

    private static final String ALGORITHM = "DES/CBC/PKCS5Padding";

    public static byte[] performLegacyEncryption(byte[] plaintext, byte[] keyBytes, byte[] ivBytes) 
            throws GeneralSecurityException {
        // Line 20: Secret key specification for legacy DES
        SecretKey key = new SecretKeySpec(keyBytes, "DES");
        
        // Line 23: Direct JCA Cipher instantiation with DES algorithm
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        
        // Line 26: Cipher initialization
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
        
        // Line 29: Final encryption operation
        return cipher.doFinal(plaintext);
    }
}
