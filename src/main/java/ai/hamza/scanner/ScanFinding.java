package ai.hamza.scanner;

import java.util.Optional;

/**
 * A normalised, <strong>content-free</strong> scanner result — the common shape into
 * which both Hamza's in-process detector and the offline oracle are mapped.
 *
 * <p>It carries the {@link ScannerSource}, the stable Hamza {@code ruleId}, an optional
 * {@link Span}, and a {@link Confidence}. It <strong>never</strong> carries the matched
 * secret value: the model has no field for it, so there is nothing to
 * accidentally persist or log.
 *
 * <p>A finding {@link #canRedact() can drive redaction} only when it has a reliable
 * span (a {@code policy.Finding} it later becomes is content-free either way).
 * Oracle-only findings that arrive without a span are Flag/Block-only by
 * construction.
 *
 * @param source     which scanner produced this
 * @param ruleId     stable Hamza rule id (native id, or {@code oracle:<rule-id>})
 * @param span       character span of the match, when known
 * @param confidence how confident the rule is that this is a real credential
 */
public record ScanFinding(ScannerSource source, String ruleId, Optional<Span> span, Confidence confidence) {

    public ScanFinding {
        if (ruleId == null || ruleId.isBlank()) {
            throw new IllegalArgumentException("ruleId must be non-blank");
        }
        span = span == null ? Optional.empty() : span;
        confidence = confidence == null ? Confidence.MEDIUM : confidence;
    }

    /** Convenience factory for a Hamza-native match with a reliable span. */
    public static ScanFinding hamza(String ruleId, Span span, Confidence confidence) {
        return new ScanFinding(ScannerSource.HAMZA, ruleId, Optional.of(span), confidence);
    }

    /** A finding can drive redaction only if it exposes a reliable span. */
    public boolean canRedact() {
        return span.isPresent();
    }
}
