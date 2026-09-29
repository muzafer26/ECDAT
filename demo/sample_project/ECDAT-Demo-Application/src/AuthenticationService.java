package com.ecdat.demo.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.GeneralSecurityException;

/**
 * AuthenticationService
 * 
 * Orchestrates session negotiation, secure persistence, and transaction signing
 * for the enterprise payment gateway microservice.
 */
public class AuthenticationService {

    private final KeyExchangeService keyExchangeService;
    private final EncryptionService encryptionService;
    private final SignatureService signatureService;

    public AuthenticationService() {
        this.keyExchangeService = new KeyExchangeService();
        this.encryptionService = new EncryptionService();
        this.signatureService = new SignatureService();
    }

    public KeyPair initiateSessionHandshake() throws GeneralSecurityException {
        return this.keyExchangeService.generateNegotiationKeyPair();
    }

    public byte[] protectSessionSecret(byte[] secret, byte[] key) throws GeneralSecurityException {
        return this.encryptionService.encryptRecord(secret, key);
    }

    public byte[] authorizeTransaction(byte[] txData, PrivateKey signingKey) throws GeneralSecurityException {
        return this.signatureService.signPayload(txData, signingKey);
    }
}
