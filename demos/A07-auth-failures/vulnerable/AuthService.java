import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * OWASP A07:2021 - Identification and Authentication Failures
 *
 * This class demonstrates three authentication weaknesses:
 *   1. Predictable session token — generated with java.util.Random (not cryptographically secure)
 *   2. No account lockout — unlimited password-guessing attempts are permitted
 *   3. Weak/default credentials — "admin"/"admin" is a valid account
 *
 * Compile: javac AuthService.java
 * Run:     java AuthService
 */
public class AuthService {

    // VULNERABILITY: Passwords stored in plaintext (also an A02 issue).
    // In a real system these would come from a database.
    private static final Map<String, String> USERS = new HashMap<>();

    // Session token -> username mapping (no expiry tracked)
    private static final Map<String, String> SESSIONS = new HashMap<>();

    static {
        USERS.put("alice", "correct-horse-battery-staple");
        // VULNERABILITY: Weak default credential that is widely known and trivially guessed.
        USERS.put("admin", "admin");
    }

    /**
     * VULNERABILITY: java.util.Random is a Linear Congruential Generator (LCG).
     * It is NOT cryptographically secure. An attacker who observes a small number
     * of generated tokens can reconstruct the internal seed and predict all future tokens.
     * Additionally, the token space is only 1,000,000 values — trivially brute-forceable.
     */
    public static String generateSessionToken() {
        // VULNERABLE: Predictable PRNG — state can be reconstructed from observed outputs
        Random random = new Random();
        // VULNERABLE: Only 6 digits = 1,000,000 possible tokens
        return String.valueOf(random.nextInt(1_000_000));
    }

    /**
     * VULNERABILITY: No attempt counter, no lockout, no delay.
     * An attacker can call this method (or its HTTP equivalent) indefinitely
     * to brute-force passwords or replay stolen credentials (credential stuffing).
     */
    public static String login(String username, String password) {
        // VULNERABILITY: No check of failed attempt count before processing
        String storedPassword = USERS.get(username);

        if (storedPassword != null && storedPassword.equals(password)) {
            String token = generateSessionToken();
            SESSIONS.put(token, username);
            // VULNERABILITY: No session expiry is recorded — tokens are valid forever
            return token;
        }

        // VULNERABILITY: Failed attempt is silently ignored — no log, no counter
        return null;
    }

    public static void main(String[] args) {
        // Demonstrate predictable token generation: tokens are sequential / clustered
        System.out.println("Token 1: " + generateSessionToken());
        System.out.println("Token 2: " + generateSessionToken());
        System.out.println("Token 3: " + generateSessionToken());

        // Demonstrate weak default credential
        String token = login("admin", "admin");
        System.out.println("Admin session token: " + token);

        // Demonstrate unlimited login attempts (no lockout after repeated failures)
        System.out.println("Attempt 1: " + login("alice", "wrong1"));
        System.out.println("Attempt 2: " + login("alice", "wrong2"));
        System.out.println("Attempt 3: " + login("alice", "wrong3"));
        // ... can continue indefinitely with no restriction
    }
}
