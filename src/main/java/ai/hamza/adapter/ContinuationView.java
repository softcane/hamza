package ai.hamza.adapter;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable, transient Adapter view of one quarantined Provider request.
 *
 * <p>The original body is retained defensively for the same Adapter to transform. Callers see
 * only decoded approved content segments; the body is never exposed by the public interface.
 */
public final class ContinuationView {

    private final String provider;
    private final byte[] originalBody;
    private final List<ContentSegment> segments;

    ContinuationView(String provider, byte[] originalBody, List<ContentSegment> segments) {
        this.provider = Objects.requireNonNull(provider, "provider");
        this.originalBody = Objects.requireNonNull(originalBody, "originalBody").clone();
        this.segments = List.copyOf(segments);
        Set<String> ids = new HashSet<>();
        for (ContentSegment segment : this.segments) {
            if (!ids.add(segment.id())) {
                throw new IllegalArgumentException("duplicate content segment id");
            }
        }
    }

    public String provider() {
        return provider;
    }

    public List<ContentSegment> segments() {
        return segments;
    }

    byte[] originalBodyCopy() {
        return originalBody.clone();
    }

    @Override
    public String toString() {
        return "ContinuationView[provider=" + provider + ", segments=" + segments.size()
                + ", bytes=" + originalBody.length + "]";
    }
}
