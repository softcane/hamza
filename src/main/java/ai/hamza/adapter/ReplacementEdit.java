package ai.hamza.adapter;

import java.util.Objects;
import java.util.regex.Pattern;

/** One decoded-text replacement requested for an Adapter-issued content segment. */
public final class ReplacementEdit {

    private static final Pattern SEGMENT_ID = Pattern.compile("[a-z][a-z0-9-]{0,63}");

    private final String segmentId;
    private final int start;
    private final int end;
    private final String replacement;

    public ReplacementEdit(String segmentId, int start, int end, String replacement) {
        if (segmentId == null || !SEGMENT_ID.matcher(segmentId).matches()) {
            throw new IllegalArgumentException("invalid content segment id");
        }
        if (start < 0 || end <= start) {
            throw new IllegalArgumentException("invalid replacement range");
        }
        this.segmentId = segmentId;
        this.start = start;
        this.end = end;
        this.replacement = Objects.requireNonNull(replacement, "replacement");
    }

    public String segmentId() {
        return segmentId;
    }

    public int start() {
        return start;
    }

    public int end() {
        return end;
    }

    public String replacement() {
        return replacement;
    }

    @Override
    public String toString() {
        return "ReplacementEdit[segmentId=" + segmentId + ", start=" + start + ", end=" + end
                + ", replacementChars=" + replacement.length() + "]";
    }
}
