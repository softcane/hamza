package ai.hamza.presidio;

import java.util.Objects;

/**
 * One transient Presidio Finding. Spans are zero-based, half-open Unicode
 * code-point offsets inside one decoded segment. Never persisted or logged.
 */
public record PresidioFinding(String entity, String segmentId, int start, int end, double score) {

    public PresidioFinding {
        Objects.requireNonNull(entity, "entity");
        Objects.requireNonNull(segmentId, "segmentId");
        if (start < 0 || end <= start) {
            throw new IllegalArgumentException("invalid code-point range");
        }
        if (!Double.isFinite(score) || score < 0.0 || score > 1.0) {
            throw new IllegalArgumentException("score must be between zero and one");
        }
    }
}
