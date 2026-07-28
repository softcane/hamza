package ai.hamza.persistence;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.policy.Action;
import ai.hamza.policy.DetectorRunEvidence;

import java.util.List;
import java.util.Set;

import java.util.Objects;

/** One immutable Turn plus optional content-free Safe Continuation evidence. */
public record TurnRecord(NormalizedTurn turn, ContinuationEvidence continuation,
                         List<DetectorRunEvidence> detectorRuns) {

    /** Always registered: a managed Turn requires a complete secret and EDM run. */
    private static final Set<String> MANDATORY_DETECTORS = Set.of("secret", "edm");
    /** Presidio joins the set only when an operator registers it. */
    private static final Set<String> KNOWN_DETECTORS = Set.of("secret", "edm", "presidio");

    public TurnRecord(NormalizedTurn turn, ContinuationEvidence continuation) {
        this(turn, continuation, List.of());
    }

    public TurnRecord {
        turn = Objects.requireNonNull(turn, "turn");
        continuation = continuation == null ? ContinuationEvidence.none() : continuation;
        detectorRuns = detectorRuns == null ? List.of() : List.copyOf(detectorRuns);
        if (continuation.role() == ContinuationEvidence.Role.SOURCE) {
            requireSource(turn, continuation);
            requireDetectorRuns(detectorRuns, false);
        } else if (continuation.role() == ContinuationEvidence.Role.DERIVED) {
            requireDerived(turn);
            requireDetectorRuns(detectorRuns, true);
        }
    }

    public static TurnRecord standard(NormalizedTurn turn) {
        return new TurnRecord(turn, ContinuationEvidence.none(), List.of());
    }

    public static TurnRecord standard(NormalizedTurn turn,
                                      List<DetectorRunEvidence> detectorRuns) {
        return new TurnRecord(turn, ContinuationEvidence.none(), detectorRuns);
    }

    private static void requireSource(NormalizedTurn turn, ContinuationEvidence continuation) {
        boolean blocked = turn.action() == Action.BLOCK && "blocked".equals(turn.status());
        boolean masked = turn.action() == Action.MASK && "withheld".equals(turn.status())
                && !turn.findings().isEmpty()
                && turn.findings().stream().allMatch(finding -> finding.action() == Action.MASK);
        if (!blocked && !masked) {
            throw new IllegalArgumentException(
                    "a source continuation Record must be Blocked or withheld with Mask");
        }
        if ((masked && continuation.maskedValueCount() <= 0)
                || (blocked && continuation.maskedValueCount() != 0)) {
            throw new IllegalArgumentException(
                    "source masked-value count must match the source Action");
        }
        if (turn.requestBytesReceived() == null || turn.requestBytesInspected() == null
                || turn.requestBytesEgressed() == null || turn.requestBytesEgressed() != 0) {
            throw new IllegalArgumentException("a source continuation Record requires complete zero-Egress accounting");
        }
        if (!turn.requestBytesReceived().equals(turn.requestBytesInspected())
                || !turn.requestBytesReceived().equals(continuation.requestBytesWithheld())) {
            throw new IllegalArgumentException("every received source byte must be inspected and withheld");
        }
    }

    private static void requireDerived(NormalizedTurn turn) {
        if (turn.action() != Action.FLAG || turn.findings().stream().anyMatch(f -> f.action() != Action.FLAG)) {
            throw new IllegalArgumentException("a derived continuation Record must be Flag-only");
        }
        if (turn.requestBytesReceived() == null || turn.requestBytesInspected() == null
                || turn.requestBytesEgressed() == null
                || turn.requestBytesReceived() < 0
                || !turn.requestBytesReceived().equals(turn.requestBytesInspected())
                || !turn.requestBytesReceived().equals(turn.requestBytesEgressed())) {
            throw new IllegalArgumentException("a derived continuation Record requires inspected Egress accounting");
        }
    }

    private static void requireDetectorRuns(List<DetectorRunEvidence> detectorRuns,
                                            boolean requireComplete) {
        Set<String> detectorIds = detectorRuns.stream()
                .map(DetectorRunEvidence::detectorId)
                .collect(java.util.stream.Collectors.toSet());
        if (detectorIds.size() != detectorRuns.size()
                || !detectorIds.containsAll(MANDATORY_DETECTORS)
                || !KNOWN_DETECTORS.containsAll(detectorIds)) {
            throw new IllegalArgumentException(
                    "a continuation Record requires one run per registered detector");
        }
        if (requireComplete && detectorRuns.stream()
                .anyMatch(run -> run.status() != ai.hamza.policy.DetectionStatus.COMPLETE)) {
            throw new IllegalArgumentException(
                    "a derived continuation Record requires complete detector runs");
        }
    }
}
