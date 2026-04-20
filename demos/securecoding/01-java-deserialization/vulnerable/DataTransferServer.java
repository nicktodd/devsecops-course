import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * Java Deserialization — Vulnerable Telemetry Ingestion Server
 *
 * Simulates a data-ingestion service that accepts serialised Java objects
 * over HTTP (a pattern seen in telemetry uplinks, internal message buses,
 * and caching layers). No class filtering is applied before deserialisation,
 * so any class on the server's classpath can be instantiated and its custom
 * readObject() hook executed — including GadgetPayload.
 *
 * Compile (all three source files together):
 *   javac DataTransferServer.java GadgetPayload.java ExploitGenerator.java
 *
 * Run:
 *   java DataTransferServer
 *
 * Then in a second terminal, generate and send the exploit payload:
 *   java ExploitGenerator
 *   curl -X POST http://localhost:8080/telemetry \
 *       --data-binary @payload.ser \
 *       -H "Content-Type: application/octet-stream"
 *
 * Expected: the server console prints "[GADGET] readObject() triggered..."
 *           confirming arbitrary code executed during deserialisation.
 */
public class DataTransferServer {

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/telemetry", new TelemetryHandler());
        server.start();
        System.out.println("[SERVER] Vulnerable telemetry server listening on :8080");
        System.out.println("[SERVER] POST serialised Java objects to http://localhost:8080/telemetry");
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
            System.out.println("[SERVER] Received " + body.length + " bytes — deserialising...");

            String responseBody;
            int status;

            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body))) {
                // VULNERABILITY: readObject() with no ObjectInputFilter.
                // The JVM will instantiate ANY Serializable class referenced in the stream
                // that exists on the server classpath, calling readObject() automatically.
                // There is no interception point between stream parsing and code execution.
                Object obj = ois.readObject(); // VULNERABLE: no class allowlist

                System.out.println("[SERVER] Deserialised object of type: " + obj.getClass().getName());
                responseBody = "Accepted: " + obj.getClass().getSimpleName();
                status = 200;
            } catch (ClassNotFoundException e) {
                System.out.println("[SERVER] Unknown class in stream: " + e.getMessage());
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
