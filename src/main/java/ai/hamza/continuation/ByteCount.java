package ai.hamza.continuation;

/** Explicit non-negative byte count used by bounded continuation state. */
public record ByteCount(long value) {
    public ByteCount {
        if (value < 0) {
            throw new IllegalArgumentException("byte count must be non-negative");
        }
    }
}
