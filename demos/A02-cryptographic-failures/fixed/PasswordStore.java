// FIX: Add jbcrypt to your Maven/Gradle dependencies:
//   Maven:  <dependency>
//             <groupId>org.mindrot</groupId>
//             <artifactId>jbcrypt</artifactId>
//             <version>0.4</version>
//           </dependency>
//   Gradle: implementation 'org.mindrot:jbcrypt:0.4'

import org.mindrot.jbcrypt.BCrypt;

/**
 * OWASP A02:2021 - Cryptographic Failures
 * Fix: Use BCrypt for password hashing.
 *
 * BCrypt is purpose-built for credential storage:
 *   - Automatically generates and embeds a unique random salt per hash
 *   - Deliberately slow (configurable work factor) — limits brute-force throughput
 *   - Same password always produces a different hash (salt is different each time)
 *   - Work factor should be increased over time as hardware improves
 *
 * Compile:  javac -cp .:jbcrypt-0.4.jar PasswordStore.java
 * Run:      java  -cp .:jbcrypt-0.4.jar PasswordStore
 */
public class PasswordStore {

    // FIX: Work factor of 12 means 2^12 = 4096 rounds of hashing.
    // Increase this value as server hardware improves (OWASP recommends >= 10).
    private static final int BCRYPT_WORK_FACTOR = 12;

    /**
     * FIX: BCrypt.hashpw() generates a unique random salt and embeds it in the output.
     * The resulting string contains the algorithm, work factor, salt, and hash —
     * everything needed for later verification.
     */
    public static String hashPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(BCRYPT_WORK_FACTOR));
    }

    /**
     * FIX: BCrypt.checkpw() extracts the embedded salt from storedHash,
     * re-hashes the input, and compares in constant time.
     * The plain-text password is never stored or logged.
     */
    public static boolean verifyPassword(String plainTextPassword, String storedHash) {
        return BCrypt.checkpw(plainTextPassword, storedHash);
    }

    public static void main(String[] args) {
        String password = "mypassword123";
        String hash = hashPassword(password);

        System.out.println("Password : " + password);
        System.out.println("BCrypt   : " + hash);
        // Output is different every run due to unique salt — rainbow tables are useless.

        System.out.println("Verified : " + verifyPassword(password, hash));
        System.out.println("Wrong pw : " + verifyPassword("wrongpassword", hash));

        // Demonstrate that two identical passwords produce DIFFERENT hashes (unique salts)
        System.out.println("Alice's hash : " + hashPassword("shared_password"));
        System.out.println("Bob's hash   : " + hashPassword("shared_password"));
        // Both hashes are different — cracking one tells you nothing about the other
    }
}
