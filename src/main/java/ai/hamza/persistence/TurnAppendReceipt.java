package ai.hamza.persistence;

/** Returned only after the immutable Turn Record transaction commits. */
public record TurnAppendReceipt(String turnId, long sequence, String entryHash) {
}
