package ai.hamza.attest;

import ai.hamza.persistence.RecoveryOutcomeAuthenticator;

import java.util.List;

/** Verifies the Recovery Outcome hash chain, launcher signature, and conflict gaps. */
public final class RecoveryOutcomeChainVerifier {

    private RecoveryOutcomeChainVerifier() {
    }

    public record Result(boolean ok, long entries, long firstBrokenSeq, String detail,
                         String headHash, long integrityGaps) {
    }

    public static Result verify(RecoveryOutcomeReader reader,
                                RecoveryOutcomeAuthenticator authenticator) {
        List<RecoveryOutcomeRow> rows = reader.allOrderedBySeq();
        long gaps = reader.integrityGapCount();
        String expectedPrev = RecordHasher.GENESIS;
        long expectedSeq = 1;
        String head = RecordHasher.GENESIS;
        for (RecoveryOutcomeRow row : rows) {
            if (row.seq() != expectedSeq) {
                return broken(rows, row.seq(), "seq gap", head, gaps);
            }
            if (!RecordHasher.CURRENT_RECOVERY_OUTCOME_VERSION.equals(row.hashVersion())) {
                return broken(rows, row.seq(), "unknown hash version", head, gaps);
            }
            if (!expectedPrev.equals(row.prevHash())) {
                return broken(rows, row.seq(), "prev_hash mismatch", head, gaps);
            }
            String recomputed = RecordHasher.recoveryOutcomeEntryHash(
                    row.prevHash(), row.hashable());
            if (!recomputed.equals(row.entryHash())) {
                return broken(rows, row.seq(), "entry_hash mismatch", head, gaps);
            }
            try {
                if (!authenticator.verify(row.outcome())) {
                    return broken(rows, row.seq(), "signature mismatch", head, gaps);
                }
            } catch (RuntimeException invalid) {
                return broken(rows, row.seq(), "malformed signed evidence", head, gaps);
            }
            expectedPrev = row.entryHash();
            head = row.entryHash();
            expectedSeq++;
        }
        if (gaps > 0) {
            return new Result(false, rows.size(), -1,
                    "evidence integrity gap", head, gaps);
        }
        return new Result(true, rows.size(), -1,
                rows.isEmpty() ? "empty outcome chain" : "ok", head, 0);
    }

    private static Result broken(List<RecoveryOutcomeRow> rows, long seq, String detail,
                                 String head, long gaps) {
        return new Result(false, rows.size(), seq, detail, head, gaps);
    }
}
