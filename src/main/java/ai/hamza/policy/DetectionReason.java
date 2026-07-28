package ai.hamza.policy;

/** Fixed, content-free reason codes for detector gaps. */
public enum DetectionReason {
    TIMEOUT,
    CONNECTION,
    BAD_RESPONSE,
    INPUT_LIMIT,
    MODEL_LIMIT,
    OUTPUT_LIMIT,
    CANCELLATION,
    DISABLED,
    UPSTREAM_BLOCK
}
