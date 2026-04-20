import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * Java Deserialization — Fix B: Replace Native Serialisation with JSON
 *
 * Eliminates the vulnerability at the root by removing ObjectInputStream entirely.
 * Jackson binds the incoming bytes to the explicit TelemetryRecord type at compile
 * time. There is no readObject() hook, no gadget chain, and no way to inject an
 * arbitrary class — the Jackson deserialiser can only produce a TelemetryRecord.
 *
 * FAIL_ON_UNKNOWN_PROPERTIES=true (default) ensures that attacker-supplied fields
 * such as @class, @type, or other polymorphism hints are rejected as errors.
 *
 * This is the preferred approach for new services. Use the ObjectInputFilter
 * approach (DataTransferServerFiltered) only when the wire format cannot change.
 *
 * Requires: Jackson Databind (see pom.xml)
 *
 * Build:
 *   mvn package
 *   java -jar target/telemetry-server-json-1.0.0.jar
 *
 * Test with a valid JSON payload:
 *   curl -X POST http://localhost:8080/telemetry \
 *       -H "Content-Type: application/json" \
 *       -d '{"satelliteId":"ESA-01","altitudeKm":408.5,"signalStrengthDbm":-78.2,"timestampEpochMs":1745000000}'
 *
 * Attempt to inject a gadget class via JSON type hint (rejected):
 *   curl -X POST http://localhost:8080/telemetry \
 *       -H "Content-Type: application/json" \
 *       -d '{"@class":"GadgetPayload","command":"touch /tmp/pwned"}'
 *   # Returns 400 — unknown field @class rejected
 */
public class DataTransferServerJson {

    // FIX: ObjectMapper bound to an explicit schema type.
    // FAIL_ON_UNKNOWN_PROPERTIES=true rejects @class/@type polymorphism hints
    // that could be used to coerce Jackson into instantiating arbitrary types.
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/telemetry", new TelemetryHandler());
        server.start();
        System.out.println("[SERVER] JSON telemetry server listening on :8080");
        System.out.println("[SERVER] Accepting JSON — no native Java serialisation.");
    }

    static class TelemetryHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                exchange.getResponseBody().close();
                return;
            }

            byte[] body = exchange.getRequestBody().readAllBytes();
            String responseBody;
            int status;

            try {
                // FIX: readValue binds the stream to TelemetryRecord — a compile-time type.
                // Jackson cannot instantiate arbitrary classes from the stream.
                // No gadget chain is possible; class loading is fully controlled by the application.
                TelemetryRecord record = MAPPER.readValue(body, TelemetryRecord.class); // FIX: explicit type

                System.out.println("[SERVER] Accepted: " + record);
                responseBody = "OK: " + record;
                status = 200;
            } catch (Exception e) {
                // FIX: Generic error message — do not expose Jackson exception details.
                System.out.println("[SERVER] Rejected invalid JSON: " + e.getMessage());
                responseBody = "Bad request";
                status = 400;
            }

            byte[] bytes = responseBody.getBytes();
            exchange.sendResponseHeaders(status, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        }
    }
}
