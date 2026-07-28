package ai.hamza.persistence;

/** Content-free result of attempting to append one terminal Recovery Outcome. */
public record RecoveryOutcomeAppendReceipt(Disposition disposition, long sequence,
                                           String entryHash) {

    public enum Disposition { APPENDED, IDEMPOTENT_REPLAY, CONFLICT_REJECTED }
}
