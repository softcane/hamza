package ai.hamza.masking;

import java.util.Objects;

/** One transient, exact, enforcing Finding presented to the Mask Planner. */
public record MaskCandidate(
        String detectorId,
        String rule,
        PlaceholderFamily family,
        String segmentId,
        int start,
        int end) {

    public MaskCandidate {
        if (detectorId == null || !detectorId.matches("secret|edm|presidio")) {
            throw new IllegalArgumentException("unknown detector id");
        }
        if (rule == null || rule.isBlank() || rule.length() > 128
                || !rule.matches("[A-Za-z0-9][A-Za-z0-9._:-]*")) {
            throw new IllegalArgumentException("rule must be a bounded identifier");
        }
        family = Objects.requireNonNull(family, "family");
        if (segmentId == null || !segmentId.matches("[a-z][a-z0-9-]{0,63}")) {
            throw new IllegalArgumentException("invalid content segment id");
        }
        if (start < 0 || end <= start) {
            throw new IllegalArgumentException("invalid code-point range");
        }
    }

    String qualifiedRule() {
        return detectorId + ':' + rule;
    }
}
