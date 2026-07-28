package ai.hamza.edm;

import java.util.Objects;

/**
 * Transient exact typed Registry occurrence in one Adapter-issued decoded segment.
 * It must never be persisted or logged.
 */
public record EdmMatch(
        String registryId,
        String fieldId,
        ReplacementKind kind,
        FullFingerprint fingerprint,
        String contentSegmentId,
        int start,
        int end) {

    public EdmMatch {
        Objects.requireNonNull(registryId, "registryId");
        Objects.requireNonNull(fieldId, "fieldId");
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(fingerprint, "fingerprint");
        Objects.requireNonNull(contentSegmentId, "contentSegmentId");
        if (start < 0 || end <= start) {
            throw new IllegalArgumentException("invalid EDM match range");
        }
    }

    @Override
    public String toString() {
        return "EdmMatch[redacted]";
    }
}
