# ECDAT Demonstration Application (FinTech Microservice Scope)

This sample project is provided for demonstration and evaluation of **ECDAT (Enterprise Cryptographic Discovery & Analysis Tool)**.

It represents a realistic enterprise microservice implementing cryptographic primitives across distinct operational roles:

## Application Services

1. **`KeyExchangeService.java`**
   * **Role:** Session Key Negotiation & Key Establishment
   * **Primitive:** Asymmetric RSA Keypair Generation (`KeyPairGenerator.getInstance("RSA")`)
   * **Operational Context:** Internet-facing API session handshake. Vulnerable to Shor's algorithm on CRQCs. Evaluated under Harvest-Now-Decrypt-Later (HNDL) exposure window.

2. **`EncryptionService.java`**
   * **Role:** Database & Storage Encryption-at-Rest
   * **Primitive:** Symmetric AES Block Cipher in GCM mode (`Cipher.getInstance("AES/GCM/NoPadding")`)
   * **Operational Context:** High-throughput transactional data persistence. Evaluated under Grover search resistance; classified as out-of-scope for public-key PQC replacement.

3. **`SignatureService.java`**
   * **Role:** Audit Evidence & Transaction Authentication
   * **Primitive:** Edwards-curve Digital Signature (`Signature.getInstance("Ed25519")`)
   * **Operational Context:** Partner API DMZ non-repudiation. Vulnerable to Shor's algorithm; maps role-specifically to post-quantum signatures (NIST FIPS 204 / 205).

4. **`AuthenticationService.java`**
   * **Role:** Security Gateway Orchestration
   * **Operational Context:** Ties together session key negotiation, encrypted payload handling, and transaction signing.

## How ECDAT Analyzes This Project

When analyzed through ECDAT:
1. **Discovery:** Identifies algorithm instantiations without presuming unevidenced properties via bounded source pattern discovery.
2. **Evidence & Provenance:** Links each finding to exact line numbers and source pattern evidence chains.
3. **Uncertainty Policy:** Preserves INDETERMINATE standing if key sizes are unstated in the source.
4. **Role-Aware Mapping:** Suggests NIST FIPS 203 (ML-KEM) for key establishment and NIST FIPS 204/205 (ML-DSA / SLH-DSA) for signatures.
5. **Human Review Gates:** Generates blocking review gates where human analyst verification is required.
