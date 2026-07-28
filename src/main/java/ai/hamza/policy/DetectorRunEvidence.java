package ai.hamza.policy;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Content-free durable projection of a {@link DetectionRun}. */
public record DetectorRunEvidence(
        String detectorId,
        String detectorVersion,
        DetectionStatus status,
        Optional<DetectionReason> reason,
        int receivedSegments,
        int inspectedSegments,
        long receivedBytes,
        long inspectedBytes,
        long durationMicros,
        int findingCount) {

    private static final Set<String> DETECTOR_IDS = Set.of("secret", "edm", "presidio");

    public DetectorRunEvidence {
        detectorId = requireDetectorId(detectorId);
        detectorVersion = requireBounded(detectorVersion, "detectorVersion");
        status = Objects.requireNonNull(status, "status");
        reason = reason == null ? Optional.empty() : reason;
        if ((status == DetectionStatus.COMPLETE) != reason.isEmpty()) {
            throw new IllegalArgumentException("only a complete detector run has no gap reason");
        }
        if (receivedSegments < 0 || inspectedSegments < 0
                || inspectedSegments > receivedSegments
                || receivedBytes < 0 || inspectedBytes < 0 || inspectedBytes > receivedBytes
                || durationMicros < 0 || findingCount < 0) {
            throw new IllegalArgumentException("invalid detector accounting");
        }
    }

    private static String requireDetectorId(String detectorId) {
        if (!DETECTOR_IDS.contains(detectorId)) {
            throw new IllegalArgumentException("unknown detector id");
        }
        return detectorId;
    }

    private static String requireBounded(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 128
                || !value.matches("[A-Za-z0-9][A-Za-z0-9._:-]*")) {
            throw new IllegalArgumentException(name + " must be a bounded identifier");
        }
        return value;
    }
}
