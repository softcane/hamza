package ai.hamza.policy;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * One bounded detector invocation. Exact spans and scores are transient; callers
 * persist only {@link #evidence()} and detector-qualified durable Findings.
 */
public record DetectionRun(
        String detectorId,
        String detectorVersion,
        DetectionStatus status,
        Optional<DetectionReason> reason,
        int receivedSegments,
        int inspectedSegments,
        long receivedBytes,
        long inspectedBytes,
        long durationMicros,
        List<DetectionFinding> findings) {

    public DetectionRun {
        Objects.requireNonNull(detectorId, "detectorId");
        Objects.requireNonNull(detectorVersion, "detectorVersion");
        status = Objects.requireNonNull(status, "status");
        reason = reason == null ? Optional.empty() : reason;
        findings = deduplicate(findings);
        new DetectorRunEvidence(detectorId, detectorVersion, status, reason,
                receivedSegments, inspectedSegments, receivedBytes, inspectedBytes,
                durationMicros, findings.size());
    }

    public DetectorRunEvidence evidence() {
        return new DetectorRunEvidence(detectorId, detectorVersion, status, reason,
                receivedSegments, inspectedSegments, receivedBytes, inspectedBytes,
                durationMicros, findings.size());
    }

    public List<Finding> durableFindings() {
        return findings.stream().map(finding -> finding.durableFinding(detectorId)).toList();
    }

    public static DetectionRun skipped(String detectorId, String version,
                                       DetectionReason reason) {
        return new DetectionRun(detectorId, version, DetectionStatus.SKIPPED,
                Optional.of(reason), 0, 0, 0, 0, 0, List.of());
    }

    private static List<DetectionFinding> deduplicate(List<DetectionFinding> findings) {
        LinkedHashMap<String, DetectionFinding> unique = new LinkedHashMap<>();
        if (findings != null) {
            for (DetectionFinding finding : findings) {
                String key = finding.rule() + '\u001f' + finding.segmentId() + '\u001f'
                        + finding.start() + '\u001f' + finding.end();
                unique.putIfAbsent(key, finding);
            }
        }
        return List.copyOf(unique.values());
    }
}
