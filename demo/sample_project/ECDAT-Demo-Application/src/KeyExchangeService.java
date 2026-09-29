package com.ecdat.demo.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * KeyExchangeService
 * 
 * Manages ephemeral and session keypair establishment for incoming API connections.
 * Uses RSA asymmetric key generation.
 */
public class KeyExchangeService {

    private final SecureRandom secureRandom;

    public KeyExchangeService() {
        this.secureRandom = new SecureRandom();
    }

    public KeyPair generateNegotiationKeyPair() throws NoSuchAlgorithmException {
        // Direct JCA KeyPairGenerator instantiation with algorithm literal "RSA"
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, this.secureRandom);
        return keyGen.generateKeyPair();
    }
}
