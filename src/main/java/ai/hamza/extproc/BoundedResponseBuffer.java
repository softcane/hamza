package ai.hamza.extproc;

import java.io.ByteArrayOutputStream;

/** Bounded transient Provider-response retention with explicit lifecycle closure. */
final class BoundedResponseBuffer implements AutoCloseable {

    private final int limit;
    private ByteArrayOutputStream bytes;
    private boolean truncated;

    BoundedResponseBuffer(int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("response limit must be positive");
        }
        this.limit = limit;
        this.bytes = new ByteArrayOutputStream(Math.min(limit, 8192));
    }

    void append(byte[] chunk) {
        ensureOpen();
        if (chunk == null || chunk.length == 0) {
            return;
        }
        int remaining = limit - bytes.size();
        int accepted = Math.min(remaining, chunk.length);
        if (accepted > 0) {
            bytes.write(chunk, 0, accepted);
        }
        truncated |= accepted < chunk.length;
    }

    byte[] snapshot() {
        ensureOpen();
        return bytes.toByteArray();
    }

    int retainedBytes() {
        return bytes == null ? 0 : bytes.size();
    }

    boolean truncated() {
        return truncated;
    }

    boolean closed() {
        return bytes == null;
    }

    @Override
    public void close() {
        if (bytes != null) {
            bytes.reset();
            bytes = null;
        }
    }

    private void ensureOpen() {
        if (closed()) {
            throw new IllegalStateException("response buffer is closed");
        }
    }
}
