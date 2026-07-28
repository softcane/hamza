package ai.hamza.continuation;

import java.util.concurrent.atomic.AtomicBoolean;

/** Idempotently releasable reservation; never owns or persists the request body. */
public final class QuarantineReservation implements AutoCloseable {

    private final QuarantineBudget owner;
    private final long reserved;
    private final AtomicBoolean closed = new AtomicBoolean();

    QuarantineReservation(QuarantineBudget owner, long reserved) {
        this.owner = owner;
        this.reserved = reserved;
    }

    public boolean acceptActual(ByteCount actual) {
        return !closed.get() && actual.value() <= reserved;
    }

    public ByteCount reservedBytes() {
        return new ByteCount(reserved);
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            owner.release(reserved);
        }
    }
}
