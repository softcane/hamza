package ai.hamza.persistence;

import ai.hamza.attest.RecordHasher;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Append-only store for signed terminal Recovery Outcomes. Turn Records are read only
 * on this path; appending an outcome can never update an Action or Egress accounting.
 */
public final class RecoveryOutcomeRepository {

    private final JdbcClient jdbc;
    private final RecoveryOutcomeAuthenticator authenticator;
    private final Clock clock;
    private final TransactionTemplate transaction;

    public RecoveryOutcomeRepository(JdbcClient jdbc,
                                     RecoveryOutcomeAuthenticator authenticator) {
        this(jdbc, authenticator, Clock.systemUTC());
    }

    public RecoveryOutcomeRepository(JdbcClient jdbc,
                                     RecoveryOutcomeAuthenticator authenticator,
                                     Clock clock) {
        this(jdbc, authenticator, clock, null);
    }

    /** Production constructor: terminal-outcome rules execute in one DB transaction. */
    public RecoveryOutcomeRepository(JdbcClient jdbc,
                                     RecoveryOutcomeAuthenticator authenticator,
                                     Clock clock,
                                     PlatformTransactionManager transactionManager) {
        this.jdbc = java.util.Objects.requireNonNull(jdbc, "jdbc");
        this.authenticator = java.util.Objects.requireNonNull(authenticator, "authenticator");
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
        this.transaction = transactionManager == null
                ? null : new TransactionTemplate(transactionManager);
        migrateSchema();
    }

    public synchronized RecoveryOutcomeAppendReceipt append(RecoveryOutcome outcome) {
        if (transaction != null) {
            return transaction.execute(status -> doAppend(outcome));
        }
        return doAppend(outcome);
    }

    private RecoveryOutcomeAppendReceipt doAppend(RecoveryOutcome outcome) {
        if (!authenticator.verify(outcome)) {
            throw rejected(RecoveryOutcomeRejectedException.Reason.INVALID_SIGNATURE);
        }
        validateLinkedTurns(outcome.evidence().recoveryId());

        Optional<StoredOutcome> existing = stored(outcome.evidence().recoveryId());
        if (existing.isPresent()) {
            StoredOutcome stored = existing.get();
            if (stored.outcome().equals(outcome)) {
                return new RecoveryOutcomeAppendReceipt(
                        RecoveryOutcomeAppendReceipt.Disposition.IDEMPOTENT_REPLAY,
                        stored.sequence(), stored.entryHash());
            }
            jdbc.sql("INSERT INTO evidence_integrity_gaps (kind, observed_at) VALUES (?, ?)")
                    .params("RECOVERY_OUTCOME_CONFLICT", clock.instant().toString()).update();
            return new RecoveryOutcomeAppendReceipt(
                    RecoveryOutcomeAppendReceipt.Disposition.CONFLICT_REJECTED,
                    stored.sequence(), stored.entryHash());
        }

        long sequence = jdbc.sql("SELECT COALESCE(MAX(seq), 0) FROM recovery_outcomes")
                .query(Long.class).single() + 1;
        String prevHash = jdbc.sql("""
                        SELECT entry_hash FROM recovery_outcomes
                        ORDER BY seq DESC LIMIT 1
                        """).query(String.class).optional().orElse(RecordHasher.GENESIS);
        String entryHash = RecordHasher.recoveryOutcomeEntryHash(prevHash, hashable(outcome));
        RecoveryOutcome.Unsigned e = outcome.evidence();
        jdbc.sql("""
                INSERT INTO recovery_outcomes (
                    recovery_id, outcome_status, agent, agent_version,
                    workflow_profile_id, workflow_profile_version, acceptance_gate_id,
                    started_at, completed_at, signature_version, signature,
                    seq, hash_version, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """).params(e.recoveryId(), e.status().wireValue(), e.agent(), e.agentVersion(),
                        e.workflowProfileId(), e.workflowProfileVersion(), e.acceptanceGateId(),
                        e.startedAt().toString(), e.completedAt().toString(),
                        outcome.signatureVersion(), outcome.signature(), sequence,
                        RecordHasher.CURRENT_RECOVERY_OUTCOME_VERSION, prevHash, entryHash)
                .update();
        return new RecoveryOutcomeAppendReceipt(
                RecoveryOutcomeAppendReceipt.Disposition.APPENDED, sequence, entryHash);
    }

    public Optional<RecoveryOutcome> find(String recoveryId) {
        return stored(recoveryId).map(StoredOutcome::outcome);
    }

    public long integrityGapCount() {
        return jdbc.sql("SELECT COUNT(*) FROM evidence_integrity_gaps")
                .query(Long.class).single();
    }

    private void validateLinkedTurns(String recoveryId) {
        List<Link> links = jdbc.sql("""
                        SELECT turn_id, record_role, parent_turn_id
                        FROM turns WHERE recovery_id = ?
                        """).param(recoveryId)
                .query((rs, n) -> new Link(rs.getString("turn_id"),
                        rs.getString("record_role"), rs.getString("parent_turn_id")))
                .list();
        Set<String> sources = new HashSet<>();
        links.stream().filter(link -> "SOURCE".equals(link.role()))
                .forEach(link -> sources.add(link.turnId()));
        List<Link> derived = links.stream().filter(link -> "DERIVED".equals(link.role())).toList();
        if (sources.isEmpty() || derived.isEmpty()) {
            throw rejected(RecoveryOutcomeRejectedException.Reason.MISSING_LINKED_TURNS);
        }
        if (derived.stream().anyMatch(link -> !sources.contains(link.parentTurnId()))) {
            throw rejected(RecoveryOutcomeRejectedException.Reason.INVALID_PARENT_LINK);
        }
    }

    private Optional<StoredOutcome> stored(String recoveryId) {
        return jdbc.sql("SELECT * FROM recovery_outcomes WHERE recovery_id = ?")
                .param(recoveryId)
                .query((rs, n) -> {
                    var unsigned = new RecoveryOutcome.Unsigned(
                            rs.getString("recovery_id"),
                            RecoveryOutcome.Status.fromWireValue(rs.getString("outcome_status")),
                            rs.getString("agent"), rs.getString("agent_version"),
                            rs.getString("workflow_profile_id"),
                            rs.getInt("workflow_profile_version"),
                            rs.getString("acceptance_gate_id"),
                            java.time.Instant.parse(rs.getString("started_at")),
                            java.time.Instant.parse(rs.getString("completed_at")));
                    RecoveryOutcome outcome = new RecoveryOutcome(unsigned,
                            rs.getString("signature_version"), rs.getString("signature"));
                    return new StoredOutcome(outcome, rs.getLong("seq"),
                            rs.getString("entry_hash"));
                }).optional();
    }

    private void migrateSchema() {
        jdbc.sql("""
                CREATE TABLE IF NOT EXISTS recovery_outcomes (
                    recovery_id TEXT PRIMARY KEY,
                    outcome_status TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    agent_version TEXT NOT NULL,
                    workflow_profile_id TEXT NOT NULL,
                    workflow_profile_version INTEGER NOT NULL,
                    acceptance_gate_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    signature_version TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    seq INTEGER NOT NULL UNIQUE,
                    hash_version TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL)
                """).update();
        jdbc.sql("""
                CREATE TABLE IF NOT EXISTS evidence_integrity_gaps (
                    gap_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    observed_at TEXT NOT NULL)
                """).update();
    }

    public static RecordHasher.RecoveryOutcomeHashFields hashable(RecoveryOutcome outcome) {
        RecoveryOutcome.Unsigned e = outcome.evidence();
        return new RecordHasher.RecoveryOutcomeHashFields(
                e.recoveryId(), e.status().wireValue(), e.agent(), e.agentVersion(),
                e.workflowProfileId(), e.workflowProfileVersion(), e.acceptanceGateId(),
                e.startedAt().toString(), e.completedAt().toString(),
                outcome.signatureVersion(), outcome.signature());
    }

    private static RecoveryOutcomeRejectedException rejected(
            RecoveryOutcomeRejectedException.Reason reason) {
        return new RecoveryOutcomeRejectedException(reason);
    }

    private record Link(String turnId, String role, String parentTurnId) {
    }

    private record StoredOutcome(RecoveryOutcome outcome, long sequence, String entryHash) {
    }
}
