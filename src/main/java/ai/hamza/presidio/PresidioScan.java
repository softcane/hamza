package ai.hamza.presidio;

import ai.hamza.policy.DetectionReason;
import ai.hamza.policy.DetectionStatus;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Transient content-free account of one bounded Presidio run over a managed Turn. */
public record PresidioScan(
        DetectionStatus status,
        Optional<DetectionReason> reason,
        List<PresidioFinding> findings,
        int receivedSegments,
        int inspectedSegments,
        long receivedBytes,
        long inspectedBytes,
        long durationMicros) {

    public PresidioScan {
        status = Objects.requireNonNull(status, "status");
        reason = reason == null ? Optional.empty() : reason;
        findings = findings == null ? List.of() : List.copyOf(findings);
    }

    public boolean complete() {
        return status == DetectionStatus.COMPLETE;
    }
}
