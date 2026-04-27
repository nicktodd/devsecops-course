package com.example.secrets;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

public class SecretManager {

    public static void main(String[] args) {
        try {
            getSecret();
        } catch (Exception e) {
            System.err.println("Error retrieving secret: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void getSecret() {

        // Can be overridden with environment variables for flexibility
        String secretName = System.getenv().getOrDefault("SECRET_NAME", "dominos-api-credentials-dev");
        String regionStr = System.getenv().getOrDefault("AWS_REGION", "eu-west-1");
        Region region = Region.of(regionStr);

        // Create a Secrets Manager client (try-with-resources ensures it is closed)
        try (SecretsManagerClient client = SecretsManagerClient.builder()
                .region(region)
                .build()) {

            GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
                    .secretId(secretName)
                    .build();

            GetSecretValueResponse getSecretValueResponse;

            try {
                getSecretValueResponse = client.getSecretValue(getSecretValueRequest);
            } catch (Exception e) {
                // For a list of exceptions thrown, see
                // https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
                throw e;
            }

            String secret = getSecretValueResponse.secretString();

            System.out.println("Successfully retrieved secret: " + secretName);
            System.out.println("Secret value: " + secret);
        }
    }
}