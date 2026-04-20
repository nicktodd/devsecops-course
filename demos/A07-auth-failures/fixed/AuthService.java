import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP A07:2021 - Identification and Authentication Failures
 *
 * Fixes applied:
 *   1. Session tokens generated with SecureRandom (256-bit — not guessable or predictable)
 *   2. Account lockout after MAX_FAILED_ATTEMPTS consecutive failures
 *   3. Session expiry enforced (30-minute TTL)
 *   4. No default weak credentials
 *   5. Failed login attempts are logged
 *
 * Note: In a real application, passwords would be hashed with BCrypt (see A02 demo).
 *       Plain-text comparison is used here to keep the focus on the auth-flow fixes.
 *
 * Compile: javac AuthService.java
 * Run:     java AuthService
 */
public class AuthService {

    private static final int    MAX_FAILED_ATTEMPTS = 5;
    private static final long   SESSION_TTL_SECONDS = 30 * 60; // 30 minutes

    // In production these would come from a database with BCrypt hashed passwords.
    private static final Map<String, String> USERS = new HashMap<>();

    // Tracks consecutive failed attempts per username
    private static final Map<String, Integer>  FAILED_ATTEMPTS = new ConcurrentHashMap<>();

    // Active sessions: token -> SessionRecord
    private static final Map<String, SessionRecord> SESSIONS = new ConcurrentHashMap<>();

    static {
        // FIX: No default or weak credentials. Passwords should be set by users
        //      during account creation, not pre-populated in source code.
        USERS.put("alice", "correct-horse-battery-staple");
    }

    // Holds the username and absolute expiry time for a session
    record SessionRecord(String username, Instant expiresAt) {}

    /**
     * FIX: SecureRandom uses the OS entropy pool (e.g. /dev/urandom) to produce
     * cryptographically unpredictable bytes. 32 bytes = 256 bits of entropy —
     * computationally infeasible to guess or reconstruct from observed outputs.
     */
    public static String generateSessionToken() {
        SecureRandom secureRandom = new SecureRandom(); // FIX: CSPRNG
        byte[] tokenBytes = new byte[32];               // FIX: 256-bit token
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * FIX: Check for account lockout before processing any credentials.
     * After MAX_FAILED_ATTEMPTS, the account is locked and further attempts are rejected
     * (a real system would also notify the account holder).
     */
    public static String login(String username, String password) {

        // FIX: Enforce lockout — reject immediately if threshold is reached
        int attempts = FAILED_ATTEMPTS.getOrDefault(username, 0);
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            System.out.println("[SECURITY] Account locked: " + username +
                               " — too many failed attempts (" + attempts + ")");
            return null;
        }

        String storedPassword = USERS.get(username);

        if (storedPassword != null && storedPassword.equals(password)) {
            // FIX: Reset the failure counter on successful authentication
            FAILED_ATTEMPTS.remove(username);

            String token = generateSessionToken();
            // FIX: Record session with an absolute expiry time
            SESSIONS.put(token, new SessionRecord(username, Instant.now().plusSeconds(SESSION_TTL_SECONDS)));

            System.out.println("[INFO] Successful login for user: " + username);
            return token;
        }

        // FIX: Increment the failure counter and log the event
        FAILED_ATTEMPTS.merge(username, 1, Integer::sum);
        int newCount = FAILED_ATTEMPTS.get(username);
        System.out.println("[SECURITY] Failed login for user: " + username +
                           " (attempt " + newCount + "/" + MAX_FAILED_ATTEMPTS + ")");
        return null;
    }

    /**
     * FIX: Validate a session token — checks existence AND expiry.
     * Expired sessions are removed from the store.
     */
    public static String validateSession(String token) {
        SessionRecord record = SESSIONS.get(token);
        if (record == null) {
            return null; // Unknown token
        }
        if (Instant.now().isAfter(record.expiresAt())) {
            SESSIONS.remove(token); // FIX: Clean up expired session
            System.out.println("[INFO] Expired session removed for user: " + record.username());
            return null;
        }
        return record.username();
    }

    public static void main(String[] args) throws InterruptedException {
        // Demonstrate unpredictable tokens: each is unique and shows no pattern
        System.out.println("Token 1: " + generateSessionToken());
        System.out.println("Token 2: " + generateSessionToken());

        // Demonstrate lockout: 5 failures lock the account
        for (int i = 1; i <= 6; i++) {
            String result = login("alice", "wrongpassword");
            System.out.println("Attempt " + i + " result: " + (result == null ? "REJECTED" : result));
        }

        // Even the correct password is rejected after lockout
        String result = login("alice", "correct-horse-battery-staple");
        System.out.println("Correct password after lockout: " + (result == null ? "REJECTED (locked)" : result));
    }
}
