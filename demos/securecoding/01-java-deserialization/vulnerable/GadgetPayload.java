import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

/**
 * Java Deserialization — Attacker-Controlled Gadget Class
 *
 * This class simulates a "deserialization gadget": a Serializable class on
 * the server's classpath whose custom readObject() performs a dangerous action
 * the moment the JVM deserialises it — with no explicit call needed by the server.
 *
 * In real-world attacks (e.g. ysoserial payloads against Apache Commons Collections),
 * the gadget chain spans multiple library classes already on the classpath.
 * This simplified version isolates the same root cause: the server cannot
 * distinguish a safe object from a weaponised one at the point of deserialisation.
 *
 * EDUCATIONAL USE ONLY — do not use against systems you do not own.
 */
public class GadgetPayload implements Serializable {

    private static final long serialVersionUID = 1L;

    // VULNERABILITY: The attacker controls this field value at serialisation time.
    // The server has no way to inspect it before readObject() fires.
    private final String command;

    public GadgetPayload(String command) {
        this.command = command;
    }

    /**
     * VULNERABILITY: readObject() is called automatically by ObjectInputStream
     * during deserialisation — the server code never explicitly invokes it.
     * Any Serializable class that overrides readObject() is a potential gadget
     * if it performs privileged operations based on attacker-controlled fields.
     *
     * The JVM invokes this hook before the server can inspect the object type,
     * so class-based checks in the server *after* readObject() are too late.
     */
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject(); // deserialise fields normally

        // VULNERABILITY: Attacker-controlled OS command executed on deserialisation.
        // The server never explicitly calls this method — the JVM invokes it automatically.
        System.out.println("[GADGET] readObject() triggered automatically — executing: " + command);
        Process p = Runtime.getRuntime().exec(command);
        try { Thread.sleep(300); } catch (InterruptedException ignored) {}
        System.out.println("[GADGET] Process started (PID " + p.pid() + ") — attacker code executed.");
    }
}
