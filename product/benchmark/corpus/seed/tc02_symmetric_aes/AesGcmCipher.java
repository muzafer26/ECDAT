package tc02;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * TC-02: Symmetric AES Authenticated Encryption (AES-GCM).
 * Purpose: Tests whether a discovery tool identifies symmetric block cipher usage,
 * extracts the cipher transformation "AES/GCM/NoPadding", and determines 256-bit key size.
 */
public class AesGcmCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BITS = 128;

    public byte[] encrypt(byte[] plaintext, byte[] keyBytes, byte[] iv) throws GeneralSecurityException {
        // Line 21: Secret key instantiation specifying AES algorithm
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        
        // Line 24: Direct JCA Cipher instantiation with AES in GCM mode without padding
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        
        // Line 27: Cipher initialization for ENCRYPT_MODE with GCM parameters
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        
        // Line 31: Execution of authenticated encryption
        return cipher.doFinal(plaintext);
    }
}
