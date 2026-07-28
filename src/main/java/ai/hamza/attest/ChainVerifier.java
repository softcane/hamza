package ai.hamza.attest;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import java.util.List;

/**
 * Walks the tamper-evident Record chain and reports OK or the
 * first broken link. Runs standalone from the fat jar (no Spring context) via the
 * PropertiesLauncher pattern — see {@code scripts/verify-chain.sh}.
 *
 * <p>What it detects: any after-the-fact edit to an accounting field or a Finding, a
 * re-ordered/forged {@code entry_hash}, and deletion of a row from the middle (the
 * next row's {@code prev_hash} no longer matches, and the {@code seq} gap shows).
 * What it cannot detect (stated honestly): truncation of the newest rows,
 * or deletion of the entire DB — the chain has no external anchor in v1.
 */
public final class ChainVerifier {

    private ChainVerifier() {
    }

    /**
     * Verdict of a chain walk. {@code firstBrokenSeq} is -1 when the chain is intact.
     * {@code legacyRows} counts pre-M10 rows that predate the chain — they are honestly
     * reported as unchained, never as tampering (the additive migration cannot
     * retroactively chain rows it didn't witness).
     */
    public record Result(boolean ok, long entries, long firstBrokenSeq, String detail,
                         String headHash, long legacyRows) {
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("usage: ChainVerifier <db-path>");
            System.exit(2);
        }
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + args[0]);
        Result r = verify(new RecordReader(JdbcClient.create(ds)));
        System.out.printf("[chain] entries=%d status=%s%n", r.entries(), r.ok() ? "OK" : "BROKEN");
        if (r.legacyRows() > 0) {
            System.out.printf("[chain] NOTE: %d row(s) predate the chain migration and are "
                    + "unchained (not covered by this verification)%n", r.legacyRows());
        }
        if (r.ok()) {
            System.out.printf("[chain] head=%s%n", r.headHash());
            System.out.println("[chain] VERDICT: OK — every link recomputes and chains cleanly");
            System.exit(0);
        }
        System.out.printf("[chain] first broken link at seq=%d: %s%n", r.firstBrokenSeq(), r.detail());
        System.out.println("[chain] VERDICT: BROKEN — the Record has been tampered with");
        System.exit(1);
    }

    /** Verify the chain over every chained Record row, in ascending {@code seq} order. */
    public static Result verify(RecordReader reader) {
        List<RecordRow> rows = reader.allOrderedBySeq();
        long legacy = reader.legacyCount();
        String legacyNote = legacy > 0
                ? " (" + legacy + " pre-migration row(s) are unchained by design)" : "";
        if (rows.isEmpty()) {
            return new Result(true, 0, -1, "empty chain" + legacyNote,
                    RecordHasher.GENESIS, legacy);
        }
        String expectedPrev = RecordHasher.GENESIS;
        long expectedSeq = 1;
        String head = RecordHasher.GENESIS;
        for (RecordRow row : rows) {
            if (row.seq() != expectedSeq) {
                return new Result(false, rows.size(), row.seq(),
                        "seq gap: expected " + expectedSeq + " but found " + row.seq()
                                + " (a row was deleted or reordered)", head, legacy);
            }
            if (!expectedPrev.equals(row.prevHash())) {
                return new Result(false, rows.size(), row.seq(),
                        "prev_hash mismatch: expected " + expectedPrev + " but row carries "
                                + row.prevHash(), head, legacy);
            }
            String hashVersion = row.hashVersion() == null
                    ? RecordHasher.LEGACY_RECORD_VERSION : row.hashVersion();
            if (!RecordHasher.isSupportedRecordVersion(hashVersion)) {
                return new Result(false, rows.size(), row.seq(),
                        "unsupported hash_version", head, legacy);
            }
            String recomputed = RecordHasher.entryHash(row.prevHash(), row.hashable());
            if (!recomputed.equals(row.entryHash())) {
                return new Result(false, rows.size(), row.seq(),
                        "entry_hash mismatch: stored " + row.entryHash() + " but content hashes to "
                                + recomputed + " (a field or Finding was altered)", head, legacy);
            }
            expectedPrev = row.entryHash();
            expectedSeq++;
            head = row.entryHash();
        }
        return new Result(true, rows.size(), -1, "ok" + legacyNote, head, legacy);
    }
}
