package tc10;

import java.util.logging.Logger;

/**
 * TC-10: Misleading Comments, Decoy Variable Names, and Logging Strings (NEGATIVE CASE).
 * Purpose: Tests false-positive resistance. Contains keywords resembling cryptography
 * (RSA, AES, DES, MD5, Cipher) in comments, variable names, and log messages,
 * but contains ZERO functional cryptographic API invocations.
 */
public class NonCryptoProcessor {

    private static final Logger logger = Logger.getLogger(NonCryptoProcessor.class.getName());

    // Line 16: Misleading comment containing crypto keywords
    // TODO: Deprecate RSA-2048 and migrate our authentication system to PQC ML-KEM

    // Line 19: Decoy variable name containing algorithm name
    private String rsaServerEndpoint = "https://gateway.internal.network/rsa-token-service";
    
    // Line 22: Decoy configuration string literal
    private String aesConfigKey = "AES_DISABLED_FOR_BATCH_PROCESSING";

    public void executeBatchProcessing() {
        // Line 26: Misleading logger message resembling crypto handshake
        logger.info("Initializing RSA secure handshake simulation for test harness...");

        // Line 29: Variable naming decoy
        int cipherBlockCount = 42;

        // Line 32: Comment with pseudo-code
        /*
         * Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
         * (This commented-out code must NOT be flagged as active cryptographic usage)
         */
        int totalItems = cipherBlockCount * 10;
        logger.info("Processed " + totalItems + " non-cryptographic records.");
    }
}
