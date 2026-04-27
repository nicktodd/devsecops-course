# Secret Manager

This project demonstrates how to use AWS Secrets Manager to retrieve secrets in a Java application. It utilizes the AWS SDK for Java and is structured as a Maven project.

## Project Structure

```
secret-manager
├── pom.xml
├── README.md
└── src
    ├── main
    │   ├── java
    │   │   └── com
    │   │       └── example
    │   │           └── secrets
    │   │               └── SecretManager.java
    │   └── resources
    │       └── application.properties
    └── test
        └── java
            └── com
                └── example
                    └── secrets
                        └── SecretManagerTest.java
```

## Prerequisites

- Java Development Kit (JDK) 8 or higher
- Apache Maven
- AWS account with access to AWS Secrets Manager

## Setup

1. Clone the repository or download the project files.
2. Navigate to the project directory.
3. Update the `src/main/resources/application.properties` file with your AWS credentials and desired region:

   ```
   aws.accessKeyId=YOUR_ACCESS_KEY_ID
   aws.secretAccessKey=YOUR_SECRET_ACCESS_KEY
   aws.region=eu-west-1
   ```

4. Build the project using Maven:

   ```
   mvn clean install
   ```

## Running the Application

To run the application, you can call the `getSecret()` method from the `SecretManager` class. Ensure that your AWS credentials are correctly set in the `application.properties` file.

## Testing

Unit tests for the `SecretManager` class are located in `src/test/java/com/example/secrets/SecretManagerTest.java`. You can run the tests using Maven:

```
mvn test
```

## License

This project is licensed under the MIT License. See the LICENSE file for more details.