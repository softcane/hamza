package ai.hamza.policy;

import java.util.Objects;

/**
 * Transient detector output. Spans use zero-based, half-open Unicode code-point
 * offsets inside one decoded segment. This type must never be persisted or logged.
 */
public record DetectionFinding(
        String rule,
        Action action,
        String segmentId,
        Integer start,
        Integer end,
        Double score,
        boolean reliableExactSpan) {

    public DetectionFinding {
        rule = requireBounded(rule, "rule");
        action = Objects.requireNonNull(action, "action");
        if (reliableExactSpan) {
            segmentId = requireBounded(segmentId, "segmentId");
            if (start == null || end == null || start < 0 || end <= start) {
                throw new IllegalArgumentException("a reliable exact span must be positive and ordered");
            }
        } else if (segmentId != null || start != null || end != null) {
            throw new IllegalArgumentException("an unreliable Finding cannot carry a span");
        }
        if (score != null && (!Double.isFinite(score) || score < 0.0 || score > 1.0)) {
            throw new IllegalArgumentException("score must be between zero and one");
        }
    }

    public Finding durableFinding(String detectorId) {
        return new Finding(detectorId, rule, action);
    }

    private static String requireBounded(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 128
                || !value.matches("[A-Za-z0-9][A-Za-z0-9._:-]*")) {
            throw new IllegalArgumentException(name + " must be a bounded identifier");
        }
        return value;
    }
}
