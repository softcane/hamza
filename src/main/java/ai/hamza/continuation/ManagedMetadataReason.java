package ai.hamza.continuation;

/** Fixed, content-free reasons for rejecting managed metadata. */
public enum ManagedMetadataReason {
    INCOMPLETE,
    DUPLICATE,
    UNKNOWN_HEADER,
    INVALID_FIELD,
    BAD_SIGNATURE,
    EXPIRED,
    FUTURE,
    PROFILE_NOT_APPROVED,
    TUPLE_NOT_APPROVED
}
