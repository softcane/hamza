package ai.hamza.persistence;

import java.time.Instant;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Signed, content-free terminal evidence from one managed recovery scope.
 * The value deliberately has no request content, Fingerprint, substitute, field id,
 * mapping, tool output, or Provider Authorization slot.
 */
public record RecoveryOutcome(Unsigned evidence, String signatureVersion, String signature) {

    private static final Pattern SIGNATURE = Pattern.compile("[0-9a-f]{64}");

    public enum Status {
        COMPLETED("completed"), FAILED("failed"), HUMAN_FALLBACK("human-fallback");

        private final String wireValue;

        Status(String wireValue) {
            this.wireValue = wireValue;
        }

        public String wireValue() {
            return wireValue;
        }

        public static Status fromWireValue(String value) {
            for (Status status : values()) {
                if (status.wireValue.equals(value)) {
                    return status;
                }
            }
            throw new IllegalArgumentException("unknown recovery outcome status");
        }
    }

    public RecoveryOutcome {
        evidence = Objects.requireNonNull(evidence, "evidence");
        if (!RecoveryOutcomeAuthenticator.SIGNATURE_VERSION.equals(signatureVersion)) {
            throw new IllegalArgumentException("unknown recovery outcome signature version");
        }
        if (signature == null || !SIGNATURE.matcher(signature).matches()) {
            throw new IllegalArgumentException("invalid recovery outcome signature");
        }
    }

    @Override
    public String toString() {
        return "RecoveryOutcome[status=" + evidence.status().wireValue()
                + ", signed=true]";
    }

    /** Unsigned content-free fields presented to the managed-launcher signer. */
    public record Unsigned(
            String recoveryId,
            Status status,
            String agent,
            String agentVersion,
            String workflowProfileId,
            int workflowProfileVersion,
            String acceptanceGateId,
            Instant startedAt,
            Instant completedAt) {

        private static final Pattern BOUNDED_ID =
                Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}");

        public Unsigned {
            recoveryId = bounded(recoveryId, "recoveryId");
            status = Objects.requireNonNull(status, "status");
            agent = bounded(agent, "agent");
            agentVersion = bounded(agentVersion, "agentVersion");
            workflowProfileId = bounded(workflowProfileId, "workflowProfileId");
            if (workflowProfileVersion <= 0) {
                throw new IllegalArgumentException("workflowProfileVersion must be positive");
            }
            acceptanceGateId = bounded(acceptanceGateId, "acceptanceGateId");
            startedAt = Objects.requireNonNull(startedAt, "startedAt");
            completedAt = Objects.requireNonNull(completedAt, "completedAt");
            if (completedAt.isBefore(startedAt)) {
                throw new IllegalArgumentException("recovery outcome timestamps are invalid");
            }
        }

        @Override
        public String toString() {
            return "RecoveryOutcome.Unsigned[status=" + status.wireValue() + "]";
        }

        private static String bounded(String value, String field) {
            if (value == null || !BOUNDED_ID.matcher(value).matches()) {
                throw new IllegalArgumentException(field + " must be a bounded internal value");
            }
            return value;
        }
    }
}
