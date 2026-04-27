import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.*;

class SecretManagerTest {

    @Test
    void testGetSecret() {
        // Arrange
        SecretManager secretManager = new SecretManager();
        String secretName = "dominos-api-credentials-dev";

        // Act
        GetSecretValueResponse response = secretManager.getSecret(secretName);

        // Assert
        assertNotNull(response);
        assertNotNull(response.secretString());
    }
}