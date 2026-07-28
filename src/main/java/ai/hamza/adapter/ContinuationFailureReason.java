package ai.hamza.adapter;

/** Fixed, content-free reasons returned by the Adapter continuation interface. */
public enum ContinuationFailureReason {
    EMPTY_BODY,
    MALFORMED_JSON,
    INVALID_REQUEST,
    UNSUPPORTED_CONTENT,
    NO_CONTENT_SEGMENTS,
    INVALID_VIEW,
    WRONG_ADAPTER,
    INVALID_DIRECTIVE,
    EMPTY_EDITS,
    UNKNOWN_SEGMENT,
    EDIT_OUT_OF_RANGE,
    OVERLAPPING_EDITS,
    MISSING_EDIT,
    TRANSFORMED_REQUEST_INVALID
}
