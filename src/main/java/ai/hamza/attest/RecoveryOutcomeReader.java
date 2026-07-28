package ai.hamza.attest;

import org.springframework.jdbc.core.simple.JdbcClient;

import java.util.List;

/** Read-only content-free view of signed Recovery Outcome evidence and integrity gaps. */
public final class RecoveryOutcomeReader {

    private final JdbcClient jdbc;
    private final boolean available;

    public RecoveryOutcomeReader(JdbcClient jdbc) {
        this.jdbc = java.util.Objects.requireNonNull(jdbc, "jdbc");
        this.available = jdbc.sql("""
                        SELECT COUNT(*) FROM sqlite_master
                        WHERE type = 'table' AND name = 'recovery_outcomes'
                        """).query(Long.class).single() > 0;
    }

    public List<RecoveryOutcomeRow> allOrderedBySeq() {
        if (!available) {
            return List.of();
        }
        return jdbc.sql("SELECT * FROM recovery_outcomes ORDER BY seq")
                .query((rs, n) -> new RecoveryOutcomeRow(
                        rs.getLong("seq"), rs.getString("hash_version"),
                        rs.getString("prev_hash"), rs.getString("entry_hash"),
                        rs.getString("recovery_id"), rs.getString("outcome_status"),
                        rs.getString("agent"), rs.getString("agent_version"),
                        rs.getString("workflow_profile_id"),
                        rs.getInt("workflow_profile_version"),
                        rs.getString("acceptance_gate_id"), rs.getString("started_at"),
                        rs.getString("completed_at"), rs.getString("signature_version"),
                        rs.getString("signature"))).list();
    }

    public long integrityGapCount() {
        long table = jdbc.sql("""
                        SELECT COUNT(*) FROM sqlite_master
                        WHERE type = 'table' AND name = 'evidence_integrity_gaps'
                        """).query(Long.class).single();
        if (table == 0) {
            return 0;
        }
        return jdbc.sql("SELECT COUNT(*) FROM evidence_integrity_gaps")
                .query(Long.class).single();
    }
}
