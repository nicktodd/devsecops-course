import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Set;

/**
 * Java Deserialization — Fix A: ObjectInputFilter Allowlist
 *
 * The server still accepts the binary serialisation format (for backward
 * compatibility with existing clients) but installs an ObjectInputFilter
 * that permits ONLY TelemetryRecord and String before any bytes are read.
 *
 * If the stream contains GadgetPayload, the filter rejects it at class
 * resolution time — before readObject() can be called. The gadget never fires.
 *
 * Requires Java 9+ (ObjectInputFilter was added in Java 9).
 *
 * Compile:
 *   javac TelemetryRecord.java DataTransferServerFiltered.java
 *
 * To demonstrate filter rejection, also compile GadgetPayload onto the classpath
 * so it is present (as it would be in a real server's dependency set):
 *   cp ../vulnerable/GadgetPayload.java .
 *   javac TelemetryRecord.java GadgetPayload.java DataTransferServerFiltered.java
 *
 * Run:
 *   java DataTransferServerFiltered
 *
 * Test with gadget payload (will be rejected):
 *   curl -X POST http://localhost:8080/telemetry \
 *       --data-binary @../vulnerable/payload.ser \
 *       -H "Content-Type: application/octet-stream"
 *   # Returns 400 — class rejected by allowlist before readObject() runs
 *
 * Test with a valid serialised TelemetryRecord — see README for helper snippet.
 */
public class DataTransferServerFiltered {

    // FIX: Explicit allowlist of classes permitted in the serialised stream.
    // Only TelemetryRecord and String (used for its satelliteId field) are allowed.
    // Every other class — including GadgetPayload and its readObject() — is rejected
    // at class-resolution time, before any constructor or hook can execute.
    private static final Set<Class<?>> ALLOWED = Set.of(TelemetryRecord.class, String.class);

    private static final ObjectInputFilter SAFE_FILTER = info -> {
        Class<?> clazz = info.serialClass();
        if (clazz == null) {
            // Null means a non-class check (e.g., depth or reference count) — pass it through.
            return ObjectInputFilter.Status.UNDECIDED;
        }
        if (clazz.isPrimitive()) {
            // Primitive field types (double, long) do not load classes — always safe.
            return ObjectInputFilter.Status.ALLOWED;
        }
        if (ALLOWED.contains(clazz)) {
            return ObjectInputFilter.Status.ALLOWED;
        }
        // FIX: Reject everything not on the allowlist — including any gadget class.
        System.out.println("[FILTER] REJECTED class not on allowlist: " + clazz.getName());
        return ObjectInputFilter.Status.REJECTED;
    };

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/telemetry", new TelemetryHandler());
        server.start();
        System.out.println("[SERVER] Filtered telemetry server listening on :8080");
        System.out.println("[SERVER] Only TelemetryRecord and String are permitted in the stream.");
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

            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body))) {
                // FIX: Install the allowlist filter BEFORE reading any bytes.
                // The filter is evaluated per class reference found in the stream.
                // Rejected classes cause a filter-specific InvalidClassException to be thrown —
                // readObject() is never called, so no gadget hook can execute.
                ois.setObjectInputFilter(SAFE_FILTER); // FIX: allowlist installed here

                Object obj = ois.readObject();
                if (obj instanceof TelemetryRecord record) {
                    System.out.println("[SERVER] Accepted: " + record);
                    responseBody = "OK: " + record;
                    status = 200;
                } else {
                    responseBody = "Unexpected type";
                    status = 400;
                }
            } catch (InvalidClassException e) {
                // FIX: Filter rejection surfaces as InvalidClassException.
                // Generic message — do not expose internal class names to the caller.
                System.out.println("[SERVER] Stream rejected by filter: " + e.getMessage());
                responseBody = "Rejected: class not permitted";
                status = 400;
            } catch (ClassNotFoundException e) {
                System.out.println("[SERVER] Unknown class: " + e.getMessage());
                responseBody = "Unknown class";
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
