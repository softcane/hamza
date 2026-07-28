package ai.hamza.policy;

import java.util.List;
import java.util.Optional;

/** Content-free detector evidence for persistence-focused test fixtures. */
public final class DetectorEvidenceFixtures {

    private DetectorEvidenceFixtures() {
    }

    public static List<DetectorRunEvidence> complete(long bytes) {
        return List.of(
                complete("secret", "fake-secret-v1", bytes),
                complete("edm", "fake-edm-v1", bytes));
    }

    private static DetectorRunEvidence complete(String detector, String version, long bytes) {
        return new DetectorRunEvidence(detector, version, DetectionStatus.COMPLETE,
                Optional.empty(), 1, 1, bytes, bytes, 1, 0);
    }
}
