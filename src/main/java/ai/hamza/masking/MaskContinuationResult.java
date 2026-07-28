package ai.hamza.masking;

import ai.hamza.policy.DetectionRun;
import ai.hamza.policy.Finding;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Outcome of the managed M2 detect/rebuild/rescan pipeline. */
public sealed interface MaskContinuationResult
        permits MaskContinuationResult.Masked, MaskContinuationResult.NotRequired,
        MaskContinuationResult.Failed {

    final class Masked implements MaskContinuationResult {
        private final byte[] derivedBody;
        private final List<DetectionRun> sourceRuns;
        private final List<DetectionRun> finalRuns;
        private final List<Finding> sourceFindings;
        private final Map<String, Integer> edmDistinctCounts;
        private final int maskedValueCount;

        public Masked(byte[] derivedBody, List<DetectionRun> sourceRuns,
                      List<DetectionRun> finalRuns, List<Finding> sourceFindings,
                      Map<String, Integer> edmDistinctCounts, int maskedValueCount) {
            this.derivedBody = Objects.requireNonNull(derivedBody, "derivedBody").clone();
            this.sourceRuns = List.copyOf(sourceRuns);
            this.finalRuns = List.copyOf(finalRuns);
            this.sourceFindings = List.copyOf(sourceFindings);
            this.edmDistinctCounts = Map.copyOf(edmDistinctCounts);
            if (maskedValueCount <= 0) {
                throw new IllegalArgumentException("masked-value count must be positive");
            }
            this.maskedValueCount = maskedValueCount;
        }

        public byte[] derivedBody() {
            return derivedBody.clone();
        }

        public List<DetectionRun> sourceRuns() {
            return sourceRuns;
        }

        public List<DetectionRun> finalRuns() {
            return finalRuns;
        }

        public List<Finding> sourceFindings() {
            return sourceFindings;
        }

        public Map<String, Integer> edmDistinctCounts() {
            return edmDistinctCounts;
        }

        public int maskedValueCount() {
            return maskedValueCount;
        }

        @Override
        public String toString() {
            return "MaskContinuationResult.Masked[bytes=" + derivedBody.length
                    + ", values=" + maskedValueCount + ']';
        }
    }

    record NotRequired(List<DetectionRun> sourceRuns) implements MaskContinuationResult {
        public NotRequired {
            sourceRuns = sourceRuns == null ? List.of() : List.copyOf(sourceRuns);
        }
    }

    record Failed(Reason reason, List<DetectionRun> sourceRuns)
            implements MaskContinuationResult {
        public Failed {
            Objects.requireNonNull(reason, "reason");
            sourceRuns = sourceRuns == null ? List.of() : List.copyOf(sourceRuns);
        }
    }

    enum Reason {
        BODY_LIMIT,
        ADAPTER_EXTRACTION,
        DETECTION_INCOMPLETE,
        BLOCKING_FINDING,
        UNRELIABLE_SPAN,
        PLAN_INVALID,
        REBUILD_FAILED,
        FINAL_SCAN_DIRTY
    }
}
