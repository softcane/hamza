package ai.hamza.continuation;

/** Deployment-wide, in-memory admission control for fully quarantined managed Turns. */
public final class QuarantineBudget {

    private final long perTurnMax;
    private final long totalMax;
    private final int maxConcurrent;
    private long reserved;
    private int active;

    public QuarantineBudget(ByteCount perTurnMax, ByteCount totalMax, int maxConcurrent) {
        if (perTurnMax.value() == 0 || totalMax.value() < perTurnMax.value()
                || maxConcurrent <= 0) {
            throw new IllegalArgumentException("invalid quarantine limits");
        }
        this.perTurnMax = perTurnMax.value();
        this.totalMax = totalMax.value();
        this.maxConcurrent = maxConcurrent;
    }

    public synchronized QuarantineAdmission tryReserve(ByteCount expected) {
        return reserve(expected.value());
    }

    public synchronized QuarantineAdmission tryReserveUnknownLength() {
        return reserve(perTurnMax);
    }

    public synchronized ByteCount reservedBytes() {
        return new ByteCount(reserved);
    }

    public synchronized boolean available() {
        return active < maxConcurrent && totalMax - reserved >= perTurnMax;
    }

    private QuarantineAdmission reserve(long bytes) {
        if (bytes > perTurnMax) {
            return new QuarantineAdmission.Denied(QuarantineDenial.PER_TURN_LIMIT);
        }
        if (active >= maxConcurrent) {
            return new QuarantineAdmission.Denied(QuarantineDenial.CONCURRENCY_LIMIT);
        }
        if (bytes > totalMax - reserved) {
            return new QuarantineAdmission.Denied(QuarantineDenial.TOTAL_MEMORY_LIMIT);
        }
        reserved += bytes;
        active++;
        return new QuarantineAdmission.Reserved(new QuarantineReservation(this, bytes));
    }

    synchronized void release(long bytes) {
        reserved -= bytes;
        active--;
        if (reserved < 0 || active < 0) {
            throw new IllegalStateException("quarantine accounting underflow");
        }
    }
}
