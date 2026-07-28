package ai.hamza.policy;

/** Completion state for one bounded detector invocation. */
public enum DetectionStatus {
    COMPLETE,
    INCOMPLETE,
    UNAVAILABLE,
    SKIPPED
}
