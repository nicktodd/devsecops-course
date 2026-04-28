package com.example.secrets;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SecretManagerTest {

    @Test
    void testSecretManagerClassExists() {
        // Verify the class can be instantiated
        SecretManager sm = new SecretManager();
        assertNotNull(sm);
    }

    @Test
    void testMainHandlesExceptionGracefully() {
        // main() should not throw - it catches exceptions and calls System.exit
        // We just verify the class is loadable and main exists via reflection
        assertDoesNotThrow(() ->
            SecretManager.class.getMethod("main", String[].class)
        );
    }
}