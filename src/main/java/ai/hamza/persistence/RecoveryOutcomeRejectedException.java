package ai.hamza.persistence;

/** Fixed, content-free rejection for invalid Recovery Outcome evidence. */
public final class RecoveryOutcomeRejectedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public enum Reason { INVALID_SIGNATURE, MISSING_LINKED_TURNS, INVALID_PARENT_LINK }

    private final Reason reason;

    public RecoveryOutcomeRejectedException(Reason reason) {
        super("recovery outcome rejected: " + reason.name());
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
