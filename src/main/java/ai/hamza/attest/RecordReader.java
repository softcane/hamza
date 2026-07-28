package ai.hamza.attest;

import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import ai.hamza.policy.DetectorRunEvidence;
import ai.hamza.policy.DetectionReason;
import ai.hamza.policy.DetectionStatus;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.HashSet;

/**
 * Read-only view over the content-free Record store for attestation. Used by both the
 * chain verifier and the report generator, so the column mapping lives in one place.
 * Never returns anything the Record does not hold — accounting + Findings only.
 */
public final class RecordReader {

    private final JdbcClient jdbc;
    private final Set<String> turnColumns;
    private final boolean hasEdmEvents;
    private final boolean hasDetectorRuns;

    public RecordReader(JdbcClient jdbc) {
        this.jdbc = jdbc;
        this.turnColumns = new HashSet<>(jdbc.sql("PRAGMA table_info(turns)")
                .query((rs, n) -> rs.getString("name")).list());
        this.hasEdmEvents = jdbc.sql("""
                        SELECT COUNT(*) FROM sqlite_master
                        WHERE type = 'table' AND name = 'edm_events'
                        """)
                .query(Long.class).single() > 0;
        this.hasDetectorRuns = jdbc.sql("""
                        SELECT COUNT(*) FROM sqlite_master
                        WHERE type = 'table' AND name = 'detector_runs'
                        """)
                .query(Long.class).single() > 0;
    }

    /**
     * Every CHAINED Record row in chain order (ascending {@code seq}), Findings attached.
     * Rows written before the M10 migration have no chain columns (NULL) — they are not
     * part of the chain and are reported separately via {@link #legacyCount()}, not
     * misread as seq 0 / broken links.
     */
    public List<RecordRow> allOrderedBySeq() {
        if (!turnColumns.contains("entry_hash")) {
            return List.of();
        }
        return read("SELECT * FROM turns WHERE entry_hash IS NOT NULL ORDER BY seq ASC",
                List.of());
    }

    /** Rows that predate the chain migration (no {@code entry_hash}); unchained by design. */
    public long legacyCount() {
        if (!turnColumns.contains("entry_hash")) {
            return jdbc.sql("SELECT COUNT(*) FROM turns").query(Long.class).single();
        }
        return jdbc.sql("SELECT COUNT(*) FROM turns WHERE entry_hash IS NULL")
                .query(Long.class).single();
    }

    /**
     * Record rows whose timestamp falls in {@code [from, to)} (ISO-8601 UTC strings sort
     * lexicographically, so a string range is a time range), in chain order.
     */
    public List<RecordRow> inWindow(String fromInclusive, String toExclusive) {
        String order = turnColumns.contains("seq") ? "seq ASC" : "ts ASC";
        return read("SELECT * FROM turns WHERE ts >= ? AND ts < ? ORDER BY " + order,
                List.of(fromInclusive, toExclusive));
    }

    private List<RecordRow> read(String sql, List<Object> params) {
        var spec = jdbc.sql(sql);
        for (int i = 0; i < params.size(); i++) {
            spec = spec.param(i + 1, params.get(i));
        }
        List<RecordRow> rows = spec.query((rs, n) -> new RecordRow(
                longValue(rs, "seq"),
                text(rs, "turn_id"),
                text(rs, "request_id"),
                text(rs, "session_id"),
                text(rs, "agent"),
                text(rs, "provider"),
                text(rs, "requested_model"),
                text(rs, "served_model"),
                text(rs, "status"),
                rs.getLong("input_tokens"),
                rs.getLong("cached_input_tokens"),
                rs.getLong("uncached_input_tokens"),
                rs.getLong("output_tokens"),
                rs.getLong("reasoning_tokens"),
                rs.getLong("total_tokens"),
                rs.getInt("tool_calls"),
                text(rs, "action"),
                rs.getLong("duration_ms"),
                text(rs, "ts"),
                text(rs, "posture"),
                text(rs, "config_fingerprint"),
                text(rs, "hash_version"),
                text(rs, "prev_hash"),
                text(rs, "entry_hash"),
                nullableLong(rs, "request_bytes_received"),
                nullableLong(rs, "request_bytes_inspected"),
                nullableLong(rs, "request_bytes_egressed"),
                new RecordHasher.ContinuationHashFields(
                        text(rs, "record_role"), text(rs, "recovery_id"),
                        text(rs, "parent_turn_id"), text(rs, "recipe_id"),
                        nullableInt(rs, "recipe_version"),
                        text(rs, "workflow_profile_id"),
                        nullableInt(rs, "workflow_profile_version"),
                        text(rs, "continuation_status"),
                        text(rs, "continuation_reason"), text(rs, "task_path"),
                        text(rs, "task_status"),
                        nullableLong(rs, "request_bytes_withheld"),
                        nullableInt(rs, "masked_value_count")),
                List.of(),
                new ArrayList<>(),
                Map.of())).list();

        // Attach Findings per row (child table), preserving a stable rule/action order.
        List<RecordRow> withFindings = new ArrayList<>(rows.size());
        for (RecordRow row : rows) {
            List<Finding> findings = jdbc.sql(
                            "SELECT detector, rule, action FROM findings WHERE turn_id = ? "
                                    + "ORDER BY detector, rule, action")
                    .param(row.turnId())
                    .query((rs, n) -> new Finding(rs.getString("detector"), rs.getString("rule"),
                            Action.valueOf(rs.getString("action"))))
                    .list();
            withFindings.add(new RecordRow(
                    row.seq(), row.turnId(), row.requestId(), row.sessionId(), row.agent(), row.provider(),
                    row.requestedModel(), row.servedModel(), row.status(),
                    row.inputTokens(), row.cachedInputTokens(), row.uncachedInputTokens(),
                    row.outputTokens(), row.reasoningTokens(), row.totalTokens(),
                    row.toolCalls(), row.action(), row.durationMs(), row.ts(),
                    row.posture(), row.configFingerprint(), row.hashVersion(), row.prevHash(), row.entryHash(),
                    row.requestBytesReceived(), row.requestBytesInspected(), row.requestBytesEgressed(),
                    row.continuation(), detectorRuns(row.turnId()), findings,
                    edmEvents(row.turnId())));
        }
        return withFindings;
    }

    private Map<String, RecordRow.EdmEvent> edmEvents(String turnId) {
        if (!hasEdmEvents) {
            return Map.of();
        }
        Map<String, RecordRow.EdmEvent> events = new TreeMap<>();
        jdbc.sql("SELECT registry, distinct_count, action FROM edm_events WHERE turn_id = ? ORDER BY registry")
                .param(turnId)
                .query((rs, n) -> new RecordRow.EdmEvent(rs.getString("registry"),
                        rs.getInt("distinct_count"), rs.getString("action")))
                .list()
                .forEach(e -> events.put(e.registry(), e));
        return events;
    }

    private List<DetectorRunEvidence> detectorRuns(String turnId) {
        if (!hasDetectorRuns) {
            return List.of();
        }
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
                        java.util.Optional.ofNullable(rs.getString("reason"))
                                .map(DetectionReason::valueOf),
                        rs.getInt("received_segments"), rs.getInt("inspected_segments"),
                        rs.getLong("received_bytes"), rs.getLong("inspected_bytes"),
                        rs.getLong("duration_micros"), rs.getInt("finding_count")))
                .list();
    }

    private String text(ResultSet rs, String column) throws SQLException {
        return turnColumns.contains(column) ? rs.getString(column) : null;
    }

    private Long nullableLong(ResultSet rs, String column) throws SQLException {
        if (!turnColumns.contains(column)) {
            return null;
        }
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private Integer nullableInt(ResultSet rs, String column) throws SQLException {
        if (!turnColumns.contains(column)) {
            return null;
        }
        int value = rs.getInt(column);
        return rs.wasNull() ? null : value;
    }

    private long longValue(ResultSet rs, String column) throws SQLException {
        return turnColumns.contains(column) ? rs.getLong(column) : 0L;
    }
}
