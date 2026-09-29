package com.ecdat.demo.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * SignatureService
 * 
 * Generates and verifies digital signatures on transaction audit logs and partner tokens.
 * Uses Ed25519 Edwards-curve signature algorithm.
 */
public class SignatureService {

    private static final String ALGORITHM = "Ed25519";

    public byte[] signPayload(byte[] payload, PrivateKey privateKey) throws GeneralSecurityException {
        // Direct Edwards-curve digital signature instantiation
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(payload);
        return signature.sign();
    }

    public boolean verifyPayload(byte[] payload, byte[] sigBytes, PublicKey publicKey) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(payload);
        return signature.verify(sigBytes);
    }
}
