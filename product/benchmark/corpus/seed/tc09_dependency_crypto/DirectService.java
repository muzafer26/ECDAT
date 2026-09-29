package tc09;

/**
 * TC-09 Service Component: Business logic without Bouncy Castle API usage.
 * Purpose: Tests whether tools distinguish library declaration from actual API invocation.
 * Contains ZERO calls to org.bouncycastle classes.
 */
public class DirectService {

    public String formatMessage(String username, String transactionId) {
        // Line 11: Standard string formatting; no cryptographic algorithms invoked
        return String.format("Transaction %s processed for user %s", transactionId, username);
    }
}
