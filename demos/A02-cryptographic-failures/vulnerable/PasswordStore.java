import java.security.MessageDigest;

/**
 * OWASP A02:2021 - Cryptographic Failures
 * Vulnerability: Passwords are hashed with MD5, which is:
 *   - Cryptographically broken (collision attacks are trivial)
 *   - Fast to compute, enabling billions of brute-force attempts per second
 *   - Unsalted, so identical passwords produce identical hashes
 *     (rainbow table attacks can crack them instantly)
 *
 * Compile:  javac PasswordStore.java
 * Run:      java PasswordStore
 *
 * Exploit:
 *   The output hash "9c87baa223f464954940f859bcf2e233" can be looked up
 *   instantly on https://crackstation.net — no compute required.
 */
public class PasswordStore {

    /**
     * VULNERABILITY: MD5 is not a password hashing algorithm.
     * It was designed for fast data integrity checks, not credential storage.
     * No salt is added, so two users with the same password get the same hash.
     */
    public static String hashPassword(String password) throws Exception {
        // VULNERABLE: MD5 is broken — do not use for password hashing
        MessageDigest md = MessageDigest.getInstance("MD5");
        // VULNERABLE: Password is encoded and hashed with no per-user salt
        byte[] hash = md.digest(password.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static boolean verifyPassword(String inputPassword, String storedHash) throws Exception {
        // VULNERABLE: Comparison is done by re-hashing the input with the same broken algorithm
        return hashPassword(inputPassword).equals(storedHash);
    }

    public static void main(String[] args) throws Exception {
        String password = "mypassword123";
        String hash = hashPassword(password);

        System.out.println("Password : " + password);
        System.out.println("MD5 Hash : " + hash);
        // Output is deterministic: 9c87baa223f464954940f859bcf2e233
        // This hash is in every public rainbow table and cracks in milliseconds.

        System.out.println("Verified : " + verifyPassword(password, hash));

        // Demonstrate that two identical passwords produce the same hash (no salt)
        System.out.println("Alice's hash : " + hashPassword("shared_password"));
        System.out.println("Bob's hash   : " + hashPassword("shared_password"));
        // Both hashes are identical — cracking one cracks both
    }
}
