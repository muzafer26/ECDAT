package com.ecdat.demo.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * EncryptionService
 * 
 * Provides symmetric encryption-at-rest for transaction records and database storage.
 * Uses AES block cipher in GCM mode.
 */
public class EncryptionService {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int IV_LENGTH_BYTES = 12;

    private final SecureRandom secureRandom = new SecureRandom();

    public byte[] encryptRecord(byte[] plaintext, byte[] rawKeyBytes) throws GeneralSecurityException {
        // Direct AES block cipher instantiation
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKey key = new SecretKeySpec(rawKeyBytes, "AES");
        
        byte[] iv = new byte[IV_LENGTH_BYTES];
        this.secureRandom.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(plaintext);
    }
}
