package ai.hamza.persistence;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.attest.RecordHasher;
import ai.hamza.config.HamzaProperties;
import ai.hamza.config.EffectiveConfigFingerprint;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import ai.hamza.policy.DetectorRunEvidence;
import ai.hamza.policy.DetectionReason;
import ai.hamza.policy.DetectionStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Writes and reads the content-free Record. Turn rows are immutable — written
 * once, never mutated. Findings are written to a child table as (turn_id, rule,
 * action) — never the matched value.
 *
 * <p>Each row also participates in a tamper-evident hash chain
 *): a monotonic {@code seq}, the previous entry's {@code entry_hash} in
 * {@code prev_hash}, and this row's SHA-256 {@code entry_hash} over its content-free
 * fields (accounting + continuation evidence + Findings + EDM events). Writes are
 * serialized so the chain stays linear even under concurrent ext_proc streams.
 */
@Repository
public class TurnRepository {

    public static final String SCHEMA_VERSION = "hamza-db/v2";

    private final JdbcClient jdbc;
    private final String posture;
    private final String configFingerprint;
    /** Null outside a Spring context (tests/CLIs); the service path is always transactional. */
    private final TransactionTemplate tx;

    /** Spring wiring: the chain records the Gate's effective posture + config fingerprint. */
    @Autowired
    public TurnRepository(JdbcClient jdbc, HamzaProperties properties,
                          PlatformTransactionManager txManager) {
        this(jdbc, properties.policy().posture().name(), fingerprintOf(properties),
                new TransactionTemplate(txManager));
    }

    /** Back-compat for callers that don't carry config (records a default fingerprint). */
    public TurnRepository(JdbcClient jdbc) {
        this(jdbc, Action.FLAG.name(), RecordHasher.configFingerprint(
                Action.FLAG.name(), java.util.Map.of(), HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                true, HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS,
                HamzaProperties.DEFAULT_EDM_BLOCK_THRESHOLD, false));
    }

    /** Explicit config, used by tests and standalone tooling (no transaction manager). */
    public TurnRepository(JdbcClient jdbc, String posture, String configFingerprint) {
        this(jdbc, posture, configFingerprint, null);
    }

    private TurnRepository(JdbcClient jdbc, String posture, String configFingerprint,
                           TransactionTemplate tx) {
        this.jdbc = jdbc;
        this.posture = posture;
        this.configFingerprint = configFingerprint;
        this.tx = tx;
        initializeFreshOrVerifySchema();
    }

    private static String fingerprintOf(HamzaProperties p) {
        return EffectiveConfigFingerprint.of(p);
    }

    private void initializeFreshOrVerifySchema() {
        long applicationTables = jdbc.sql("""
                        SELECT COUNT(*) FROM sqlite_master
                        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                        """)
                .query(Long.class).single();
        if (applicationTables == 0) {
            initializeFreshSchema();
        }
        boolean hasMetadata = jdbc.sql("""
                        SELECT COUNT(*) FROM sqlite_master
                        WHERE type = 'table' AND name = 'schema_metadata'
                        """)
                .query(Long.class).single() == 1;
        if (!hasMetadata) {
            throw new IllegalStateException("legacy Hamza database refused; expected "
                    + SCHEMA_VERSION + ". Back up and reset the database before startup");
        }
        String actual = jdbc.sql("SELECT version FROM schema_metadata WHERE singleton = 1")
                .query(String.class).optional().orElse("missing");
        if (!SCHEMA_VERSION.equals(actual)) {
            throw new IllegalStateException("unsupported Hamza database schema " + actual
                    + "; expected " + SCHEMA_VERSION);
        }
        verifyV2Shape();
    }

    private void initializeFreshSchema() {
        String schema;
        try (var input = TurnRepository.class.getResourceAsStream("/schema.sql")) {
            if (input == null) {
                throw new IllegalStateException("schema.sql is missing");
            }
            schema = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new IllegalStateException("schema.sql could not be read", exception);
        }
        for (String statement : schema.split(";")) {
            if (!statement.isBlank()) {
                jdbc.sql(statement).update();
            }
        }
    }

    private void verifyV2Shape() {
        List<String> tables = jdbc.sql("""
                        SELECT name FROM sqlite_master
                        WHERE type = 'table' AND name IN ('turns', 'findings', 'detector_runs')
                        ORDER BY name
                        """)
                .query(String.class).list();
        List<String> findingColumns = jdbc.sql("PRAGMA table_info(findings)")
                .query((rs, row) -> rs.getString("name")).list();
        List<String> turnColumns = jdbc.sql("PRAGMA table_info(turns)")
                .query((rs, row) -> rs.getString("name")).list();
        if (!tables.equals(List.of("detector_runs", "findings", "turns"))
                || !findingColumns.containsAll(List.of("turn_id", "detector", "rule", "action"))
                || !turnColumns.contains("masked_value_count")) {
            throw new IllegalStateException("invalid Hamza database schema shape for "
                    + SCHEMA_VERSION);
        }
    }

    /**
     * Append one Turn to the Record store and to the hash chain. Synchronized so the
     * read-tip / compute / insert sequence is atomic w.r.t. other writers — the SQLite
     * pool is size 1, but multiple ext_proc streams call this concurrently. In a Spring
     * context the turn row and its findings commit in ONE transaction: the entry_hash
     * commits to the finding keys, so a torn write (turn without findings) would make
     * the verifier report tampering for what was only a crash.
     */
    public void save(NormalizedTurn t) {
        append(TurnRecord.standard(t));
    }

    /**
     * Append an immutable Turn Record. The receipt is returned only after the Spring
     * transaction commits; persistence failures propagate to the caller so a source
     * Record can gate release of its derived Turn.
     */
    public synchronized TurnAppendReceipt append(TurnRecord record) {
        if (tx != null) {
            return tx.execute(status -> doAppend(record));
        }
        return doAppend(record);
    }

    private TurnAppendReceipt doAppend(TurnRecord record) {
        NormalizedTurn t = record.turn();
        ContinuationEvidence continuation = record.continuation();
        validateParent(continuation);
        long seq = jdbc.sql("SELECT COALESCE(MAX(seq), 0) FROM turns").query(Long.class).single() + 1;
        // Pre-migration rows carry NULL entry_hash; the chain tip is the newest CHAINED row.
        String prevHash = jdbc.sql(
                        "SELECT entry_hash FROM turns WHERE entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1")
                .query(String.class).optional().orElse(RecordHasher.GENESIS);

        List<String> findingKeys = new ArrayList<>(t.findings().size());
        for (Finding f : t.findings()) {
            findingKeys.add(RecordHasher.findingKey(f.detector(), f.rule(), f.action().name()));
        }
        List<String> detectorRunKeys = record.detectorRuns().stream()
                .map(TurnRepository::detectorRunKey)
                .toList();
        List<String> edmEventKeys = new ArrayList<>(t.edmDistinctCounts().size());
        t.edmDistinctCounts().forEach((registry, count) -> edmEventKeys.add(
                RecordHasher.edmEventKey(registry, count,
                        actionForEdmRule(t.findings(), registry).name())));
        var continuationHash = new RecordHasher.ContinuationHashFields(
                continuation.role().name(), continuation.recoveryId(),
                continuation.parentTurnId(), continuation.recipeId(),
                continuation.recipeVersion(), continuation.workflowProfileId(),
                continuation.workflowProfileVersion(),
                enumName(continuation.continuationStatus()), continuation.reasonCode(),
                continuation.taskPath(), enumName(continuation.taskStatus()),
                continuation.requestBytesWithheld(), continuation.maskedValueCount());
        var hashable = new RecordHasher.HashableTurn(
                RecordHasher.CURRENT_RECORD_VERSION, t.turnId(), t.requestId(),
                t.sessionId(), t.agent(), t.provider(), t.requestedModel(),
                t.servedModel(), t.status(), t.inputTokens(), t.cachedInputTokens(),
                t.uncachedInputTokens(), t.outputTokens(), t.reasoningTokens(),
                t.totalTokens(), t.toolCalls(), t.action().name(), t.durationMs(),
                t.timestamp().toString(), posture, configFingerprint,
                t.requestBytesReceived(), t.requestBytesInspected(),
                t.requestBytesEgressed(), continuationHash, edmEventKeys, detectorRunKeys,
                findingKeys);
        String entryHash = RecordHasher.entryHash(prevHash, hashable);

        jdbc.sql("""
                INSERT INTO turns (turn_id, session_id, agent, provider, requested_model,
                                   served_model, status, input_tokens, cached_input_tokens,
                                   uncached_input_tokens, output_tokens, reasoning_tokens,
                                   total_tokens, tool_calls, action, duration_ms, ts,
                                   request_id, request_bytes_received, request_bytes_inspected,
                                   request_bytes_egressed, record_role, recovery_id, parent_turn_id,
                                   recipe_id, recipe_version, workflow_profile_id,
                                   workflow_profile_version, continuation_status,
                                   continuation_reason, task_path, task_status,
                                   request_bytes_withheld, masked_value_count, seq, posture, config_fingerprint,
                                   hash_version, prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """)
                .params(t.turnId(), t.sessionId(), t.agent(), t.provider(), t.requestedModel(),
                        t.servedModel(), t.status(), t.inputTokens(), t.cachedInputTokens(),
                        t.uncachedInputTokens(), t.outputTokens(), t.reasoningTokens(),
                        t.totalTokens(), t.toolCalls(), t.action().name(), t.durationMs(),
                        t.timestamp().toString(), t.requestId(), t.requestBytesReceived(),
                        t.requestBytesInspected(), t.requestBytesEgressed(),
                        continuation.role().name(), continuation.recoveryId(),
                        continuation.parentTurnId(), continuation.recipeId(),
                        continuation.recipeVersion(), continuation.workflowProfileId(),
                        continuation.workflowProfileVersion(), enumName(continuation.continuationStatus()),
                        continuation.reasonCode(), continuation.taskPath(),
                        enumName(continuation.taskStatus()), continuation.requestBytesWithheld(),
                        continuation.maskedValueCount(), seq, posture,
                        configFingerprint, RecordHasher.CURRENT_RECORD_VERSION, prevHash, entryHash)
                .update();

        for (Finding f : t.findings()) {
            jdbc.sql("INSERT INTO findings (turn_id, detector, rule, action) VALUES (?, ?, ?, ?)")
                    .params(t.turnId(), f.detector(), f.rule(), f.action().name())
                    .update();
        }
        for (DetectorRunEvidence run : record.detectorRuns()) {
            jdbc.sql("""
                    INSERT INTO detector_runs (
                        turn_id, detector, detector_version, status, reason,
                        received_segments, inspected_segments, received_bytes,
                        inspected_bytes, duration_micros, finding_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """)
                    .params(t.turnId(), run.detectorId(), run.detectorVersion(),
                            run.status().name(), run.reason().map(Enum::name).orElse(null),
                            run.receivedSegments(), run.inspectedSegments(), run.receivedBytes(),
                            run.inspectedBytes(), run.durationMicros(), run.findingCount())
                    .update();
        }
        t.edmDistinctCounts().forEach((registry, count) -> {
            Action eventAction = actionForEdmRule(t.findings(), registry);
            jdbc.sql("INSERT INTO edm_events (turn_id, registry, distinct_count, action) VALUES (?, ?, ?, ?)")
                    .params(t.turnId(), registry, count, eventAction.name())
                    .update();
        });
        return new TurnAppendReceipt(t.turnId(), seq, entryHash);
    }

    public long count() {
        return jdbc.sql("SELECT COUNT(*) FROM turns").query(Long.class).single();
    }

    public Optional<NormalizedTurn> findById(String turnId) {
        return findRecordById(turnId).map(TurnRecord::turn);
    }

    public Optional<TurnRecord> findRecordById(String turnId) {
        List<Finding> findings = jdbc.sql(
                        "SELECT detector, rule, action FROM findings WHERE turn_id = ?")
                .param(turnId)
                .query((rs, n) -> new Finding(rs.getString("detector"), rs.getString("rule"),
                        Action.valueOf(rs.getString("action"))))
                .list();
        List<DetectorRunEvidence> detectorRuns = readDetectorRuns(turnId);

        return jdbc.sql("SELECT * FROM turns WHERE turn_id = ?")
                .param(turnId)
                .query((rs, n) -> new TurnRecord(new NormalizedTurn(
                        rs.getString("turn_id"),
                        rs.getString("session_id"),
                        rs.getString("agent"),
                        rs.getString("provider"),
                        rs.getString("requested_model"),
                        rs.getString("served_model"),
                        rs.getString("status"),
                        rs.getLong("input_tokens"),
                        rs.getLong("cached_input_tokens"),
                        rs.getLong("uncached_input_tokens"),
                        rs.getLong("output_tokens"),
                        rs.getLong("reasoning_tokens"),
                        rs.getLong("total_tokens"),
                        rs.getInt("tool_calls"),
                        new ArrayList<>(findings),
                        Action.valueOf(rs.getString("action")),
                        rs.getLong("duration_ms"),
                        Instant.parse(rs.getString("ts")),
                        rs.getString("request_id"),
                        nullableLong(rs, "request_bytes_received"),
                        nullableLong(rs, "request_bytes_inspected"),
                        nullableLong(rs, "request_bytes_egressed"),
                        readEdmCounts(turnId)),
                        ContinuationEvidence.restore(rs.getString("record_role"),
                                rs.getString("recovery_id"), rs.getString("parent_turn_id"),
                                rs.getString("recipe_id"), nullableInt(rs, "recipe_version"),
                                rs.getString("workflow_profile_id"),
                                nullableInt(rs, "workflow_profile_version"),
                                rs.getString("continuation_status"),
                                rs.getString("continuation_reason"), rs.getString("task_path"),
                                rs.getString("task_status"), nullableLong(rs, "request_bytes_withheld"),
                                nullableInt(rs, "masked_value_count")),
                        detectorRuns))
                .optional();
    }

    private void validateParent(ContinuationEvidence continuation) {
        if (continuation.role() != ContinuationEvidence.Role.DERIVED) {
            return;
        }
        var parent = jdbc.sql("SELECT record_role, recovery_id FROM turns WHERE turn_id = ?")
                .param(continuation.parentTurnId())
                .query((rs, n) -> java.util.Map.entry(rs.getString("record_role"),
                        rs.getString("recovery_id")))
                .optional()
                .orElseThrow(() -> new IllegalStateException("derived Record parent is missing"));
        if (!ContinuationEvidence.Role.SOURCE.name().equals(parent.getKey())
                || !continuation.recoveryId().equals(parent.getValue())) {
            throw new IllegalStateException("derived Record parent linkage is invalid");
        }
    }

    private static Action actionForEdmRule(List<Finding> findings, String registry) {
        String rule = "edm-" + registry;
        for (Finding f : findings) {
            if (rule.equals(f.rule())) {
                return f.action();
            }
        }
        return Action.FLAG;
    }

    private java.util.Map<String, Integer> readEdmCounts(String turnId) {
        return jdbc.sql("SELECT registry, distinct_count FROM edm_events WHERE turn_id = ?")
                .param(turnId)
                .query((rs, n) -> java.util.Map.entry(rs.getString("registry"),
                        rs.getInt("distinct_count")))
                .list()
                .stream()
                .collect(java.util.stream.Collectors.toMap(java.util.Map.Entry::getKey,
                        java.util.Map.Entry::getValue));
    }

    private List<DetectorRunEvidence> readDetectorRuns(String turnId) {
        return jdbc.sql("""
                        SELECT detector, detector_version, status, reason,
                               received_segments, inspected_segments, received_bytes,
                               inspected_bytes, duration_micros, finding_count
                        FROM detector_runs WHERE turn_id = ? ORDER BY detector
                        """)
                .param(turnId)
                .query((rs, n) -> new DetectorRunEvidence(
                        rs.getString("detector"), rs.getString("detector_version"),
                        DetectionStatus.valueOf(rs.getString("status")),
                        Optional.ofNullable(rs.getString("reason")).map(DetectionReason::valueOf),
                        rs.getInt("received_segments"), rs.getInt("inspected_segments"),
                        rs.getLong("received_bytes"), rs.getLong("inspected_bytes"),
                        rs.getLong("duration_micros"), rs.getInt("finding_count")))
                .list();
    }

    private static String detectorRunKey(DetectorRunEvidence run) {
        return RecordHasher.detectorRunKey(run.detectorId(), run.detectorVersion(),
                run.status().name(), run.reason().map(Enum::name).orElse(null),
                run.receivedSegments(), run.inspectedSegments(), run.receivedBytes(),
                run.inspectedBytes(), run.durationMicros(), run.findingCount());
    }

    private static Long nullableLong(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private static Integer nullableInt(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        int value = rs.getInt(column);
        return rs.wasNull() ? null : value;
    }

    private static String enumName(Enum<?> value) {
        return value == null ? null : value.name();
    }
}
