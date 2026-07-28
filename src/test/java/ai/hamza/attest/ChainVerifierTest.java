package ai.hamza.attest;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.persistence.TurnRepository;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The M10 chain invariants: appending Turns builds a chain that
 * verifies OK, and any after-the-fact edit or deletion breaks it at the first affected
 * link. Uses the REAL {@link TurnRepository} write path and {@link ChainVerifier}.
 */
class ChainVerifierTest {

    private static final String FP = "test-fingerprint";

    private static JdbcClient jdbcOn(Path dbFile) {
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + dbFile);
        applySchema(ds);
        return JdbcClient.create(ds);
    }

    private static void applySchema(DataSource ds) {
        String schema;
        try (var in = ChainVerifierTest.class.getResourceAsStream("/schema.sql")) {
            schema = new String(in.readAllBytes());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        try (var conn = ds.getConnection(); var st = conn.createStatement()) {
            for (String stmt : schema.split(";")) {
                if (!stmt.isBlank()) {
                    st.execute(stmt);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static NormalizedTurn turn(String id, int inTok, List<Finding> findings, Action action) {
        return new NormalizedTurn(id, "sess", "codex", "openai", "gpt-5-codex", "gpt-5-codex",
                "completed", inTok, 0, inTok, 10, 0, inTok + 10, 0, findings, action, 5L,
                Instant.parse("2026-07-06T10:0" + (id.charAt(id.length() - 1)) + ":00Z"));
    }

    @Test
    void appendedTurnsFormAVerifiableChain(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("chain.db"));
        TurnRepository repo = new TurnRepository(jdbc, "MASK", FP);
        repo.save(turn("t1", 100, List.of(), Action.FLAG));
        repo.save(turn("t2", 200, List.of(new Finding("aws-access-key-id", Action.MASK)), Action.MASK));
        repo.save(turn("t3", 300, List.of(), Action.FLAG));

        ChainVerifier.Result r = ChainVerifier.verify(new RecordReader(jdbc));
        assertThat(r.ok()).isTrue();
        assertThat(r.entries()).isEqualTo(3);
        assertThat(r.firstBrokenSeq()).isEqualTo(-1);
        assertThat(r.headHash()).hasSize(64);
    }

    @Test
    void emptyStoreIsAValidChain(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("empty.db"));
        new TurnRepository(jdbc, "FLAG", FP); // runs migration, writes nothing
        ChainVerifier.Result r = ChainVerifier.verify(new RecordReader(jdbc));
        assertThat(r.ok()).isTrue();
        assertThat(r.entries()).isZero();
    }

    @Test
    void preMigrationRowsAreReportedUnchainedNotTampered(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("legacy.db"));
        // A row written before M10: no seq/posture/fingerprint/hash columns filled.
        jdbc.sql("""
                INSERT INTO turns (turn_id, session_id, agent, provider, requested_model,
                                   served_model, status, input_tokens, cached_input_tokens,
                                   uncached_input_tokens, output_tokens, reasoning_tokens,
                                   total_tokens, tool_calls, action, duration_ms, ts)
                VALUES ('legacy1', 'sess', 'codex', 'openai', 'gpt-5-codex', 'gpt-5-codex',
                        'completed', 10, 0, 10, 5, 0, 15, 0, 'FLAG', 5,
                        '2026-07-01T00:00:00Z')
                """).update();

        TurnRepository repo = new TurnRepository(jdbc, "FLAG", FP);
        repo.save(turn("t1", 100, List.of(), Action.FLAG));

        ChainVerifier.Result r = ChainVerifier.verify(new RecordReader(jdbc));
        assertThat(r.ok()).isTrue();
        assertThat(r.entries()).isEqualTo(1);
        assertThat(r.legacyRows()).isEqualTo(1);
        assertThat(r.detail()).contains("unchained");
    }

    @Test
    void existingV2ChainedRowsStillVerifyAfterRequestIdSchemaAddition(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("v2.db"));
        var hashable = new RecordHasher.HashableTurn(
                RecordHasher.LEGACY_RECORD_VERSION, "v2-turn", null, "sess", "codex",
                "openai", "gpt-5-codex", "gpt-5-codex", "completed",
                10, 0, 10, 5, 0, 15, 0, "FLAG", 5,
                "2026-07-06T10:00:00Z", "FLAG", FP, List.of());
        String entryHash = RecordHasher.entryHash(RecordHasher.GENESIS, hashable);
        jdbc.sql("""
                INSERT INTO turns (turn_id, session_id, agent, provider, requested_model,
                                   served_model, status, input_tokens, cached_input_tokens,
                                   uncached_input_tokens, output_tokens, reasoning_tokens,
                                   total_tokens, tool_calls, action, duration_ms, ts,
                                   seq, posture, config_fingerprint, prev_hash, entry_hash)
                VALUES ('v2-turn', 'sess', 'codex', 'openai', 'gpt-5-codex', 'gpt-5-codex',
                        'completed', 10, 0, 10, 5, 0, 15, 0, 'FLAG', 5,
                        '2026-07-06T10:00:00Z', 1, 'FLAG', ?, ?, ?)
                """).params(FP, RecordHasher.GENESIS, entryHash).update();

        ChainVerifier.Result r = ChainVerifier.verify(new RecordReader(jdbc));

        assertThat(r.ok()).isTrue();
        assertThat(r.entries()).isEqualTo(1);
    }

    @Test
    void existingV3ChainedRowsStillVerifyAfterContinuationSchemaAddition(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("v3.db"));
        var hashable = new RecordHasher.HashableTurn(
                RecordHasher.REQUEST_ID_RECORD_VERSION, "v3-turn", "request-1", "sess",
                "codex", "openai", "gpt-5-codex", "gpt-5-codex", "completed",
                10, 0, 10, 5, 0, 15, 0, "FLAG", 5,
                "2026-07-06T10:00:00Z", "FLAG", FP, List.of());
        String entryHash = RecordHasher.entryHash(RecordHasher.GENESIS, hashable);
        jdbc.sql("""
                INSERT INTO turns (turn_id, session_id, agent, provider, requested_model,
                                   served_model, status, input_tokens, cached_input_tokens,
                                   uncached_input_tokens, output_tokens, reasoning_tokens,
                                   total_tokens, tool_calls, action, duration_ms, ts, request_id,
                                   seq, posture, config_fingerprint, hash_version, prev_hash, entry_hash)
                VALUES ('v3-turn', 'sess', 'codex', 'openai', 'gpt-5-codex', 'gpt-5-codex',
                        'completed', 10, 0, 10, 5, 0, 15, 0, 'FLAG', 5,
                        '2026-07-06T10:00:00Z', 'request-1', 1, 'FLAG', ?, ?, ?, ?)
                """).params(FP, RecordHasher.REQUEST_ID_RECORD_VERSION,
                        RecordHasher.GENESIS, entryHash).update();

        ChainVerifier.Result result = ChainVerifier.verify(new RecordReader(jdbc));

        assertThat(result.ok()).isTrue();
        assertThat(result.entries()).isEqualTo(1);
    }

    @Test
    void editingAnAccountingFieldBreaksTheChain(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("tamper.db"));
        TurnRepository repo = new TurnRepository(jdbc, "MASK", FP);
        repo.save(turn("t1", 100, List.of(), Action.FLAG));
        repo.save(turn("t2", 200, List.of(), Action.FLAG));

        // Tamper: rewrite the recorded token count of the first Turn but leave its
        // stored entry_hash untouched — exactly what an attacker editing the DB would do.
        jdbc.sql("UPDATE turns SET input_tokens = 999999 WHERE turn_id = 't1'").update();

        ChainVerifier.Result r = ChainVerifier.verify(new RecordReader(jdbc));
        assertThat(r.ok()).isFalse();
        assertThat(r.firstBrokenSeq()).isEqualTo(1);
        assertThat(r.detail()).contains("entry_hash mismatch");
    }

    @Test
    void editingAFindingBreaksTheChain(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("finding.db"));
        TurnRepository repo = new TurnRepository(jdbc, "MASK", FP);
        repo.save(turn("t1", 100, List.of(new Finding("aws-access-key-id", Action.MASK)), Action.MASK));

        // Remove the Finding row — the accounting is intact but the Findings set changed.
        jdbc.sql("DELETE FROM findings WHERE turn_id = 't1'").update();

        ChainVerifier.Result r = ChainVerifier.verify(new RecordReader(jdbc));
        assertThat(r.ok()).isFalse();
        assertThat(r.firstBrokenSeq()).isEqualTo(1);
    }

    @Test
    void deletingAMiddleRowBreaksTheChain(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("delete.db"));
        TurnRepository repo = new TurnRepository(jdbc, "FLAG", FP);
        repo.save(turn("t1", 100, List.of(), Action.FLAG));
        repo.save(turn("t2", 200, List.of(), Action.FLAG));
        repo.save(turn("t3", 300, List.of(), Action.FLAG));

        jdbc.sql("DELETE FROM turns WHERE seq = 2").update();

        ChainVerifier.Result r = ChainVerifier.verify(new RecordReader(jdbc));
        assertThat(r.ok()).isFalse();
        // The row that was seq=3 is now where seq=2 was expected: a seq gap.
        assertThat(r.detail()).contains("seq gap");
    }
}
