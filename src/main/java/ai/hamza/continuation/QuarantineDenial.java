package ai.hamza.continuation;

/** Fixed, content-free quarantine admission failures. */
public enum QuarantineDenial {
    PER_TURN_LIMIT,
    TOTAL_MEMORY_LIMIT,
    CONCURRENCY_LIMIT
}
