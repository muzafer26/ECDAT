package tc08;

import java.security.GeneralSecurityException;

/**
 * TC-08 Application Component: Business Layer calling internal helper.
 * Purpose: Tests whether a discovery tool can connect business logic invocation
 * to the underlying wrapped cryptographic primitive or at least detect the wrapper call.
 */
public class DataEncryptor {

    public byte[] processCustomerRecord(byte[] customerData, byte[] keyBytes, byte[] ivBytes) 
            throws GeneralSecurityException {
        // Line 15: Application layer invokes internal wrapper class rather than direct JCA Cipher
        return LegacyCryptoHelper.performLegacyEncryption(customerData, keyBytes, ivBytes);
    }
}
