import java.io.Serializable;

/**
 * Safe, schema-bound data transfer object for satellite telemetry.
 *
 * This is the ONLY class the server is permitted to deserialise.
 * Its fields are all primitives and String — no executable hooks,
 * no transient state, no custom readObject().
 *
 * Used by both fix approaches:
 *   - DataTransferServerFiltered (ObjectInputFilter allowlist)
 *   - DataTransferServerJson     (Jackson binding target — no Serializable needed for JSON)
 */
public class TelemetryRecord implements Serializable {

    private static final long serialVersionUID = 1L;

    private String satelliteId;
    private double altitudeKm;
    private double signalStrengthDbm;
    private long   timestampEpochMs;

    // Default constructor required by Jackson
    public TelemetryRecord() {}

    public TelemetryRecord(String satelliteId, double altitudeKm,
                           double signalStrengthDbm, long timestampEpochMs) {
        this.satelliteId         = satelliteId;
        this.altitudeKm          = altitudeKm;
        this.signalStrengthDbm   = signalStrengthDbm;
        this.timestampEpochMs    = timestampEpochMs;
    }

    public String getSatelliteId()       { return satelliteId; }
    public double getAltitudeKm()        { return altitudeKm; }
    public double getSignalStrengthDbm() { return signalStrengthDbm; }
    public long   getTimestampEpochMs()  { return timestampEpochMs; }

    @Override
    public String toString() {
        return "TelemetryRecord{id='" + satelliteId + "', altKm=" + altitudeKm
                + ", signal=" + signalStrengthDbm + "dBm, ts=" + timestampEpochMs + "}";
    }
}
