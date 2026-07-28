package ai.hamza.scanner;

/**
 * A half-open character span {@code [start, end)} into the scanned text. Carries only
 * offsets — never the matched text — so it stays content-free.
 *
 * <p>A span is what makes reliable redaction possible. A {@link ScanFinding} without a
 * span may only Flag or Block, never Redact.
 */
public record Span(int start, int end) {

    public Span {
        if (start < 0 || end < start) {
            throw new IllegalArgumentException("invalid span [" + start + ", " + end + ")");
        }
    }

    public int length() {
        return end - start;
    }

    /** True if this span overlaps {@code other} (shared half-open range). */
    public boolean overlaps(Span other) {
        return start < other.end && other.start < end;
    }
}
