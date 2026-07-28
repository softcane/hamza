package ai.hamza.persistence;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.attest.ChainVerifier;
import ai.hamza.attest.RecordHasher;
import ai.hamza.attest.RecordReader;
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
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static ai.hamza.policy.DetectorEvidenceFixtures.complete;

class TurnRepositoryContinuationTest {

    @Test
    void appendsAndReadsLinkedSourceAndDerivedRecords(@TempDir Path tmp) {
        TurnRepository repository = new TurnRepository(jdbcOn(tmp.resolve("linked.db")));

        TurnRecord source = new TurnRecord(sourceTurn("source-1"), ContinuationEvidence.source(
                "recovery-1", "synthetic-email", 1, "repo-safe-edit", 1,
                "one-way", "eligible-edm", 128), complete(128));

        TurnAppendReceipt sourceReceipt = repository.append(source);

        assertThat(sourceReceipt.turnId()).isEqualTo("source-1");
        assertThat(sourceReceipt.entryHash()).hasSize(64);
        assertThat(jdbcOnExisting(tmp.resolve("linked.db")).sql(
                        "SELECT hash_version FROM turns WHERE turn_id = 'source-1'")
                .query(String.class).single()).isEqualTo(RecordHasher.CURRENT_RECORD_VERSION);
        TurnRecord storedSource = repository.findRecordById("source-1").orElseThrow();
        assertThat(storedSource.continuation().role()).isEqualTo(ContinuationEvidence.Role.SOURCE);
        assertThat(storedSource.turn().action()).isEqualTo(Action.BLOCK);
        assertThat(storedSource.turn().requestBytesEgressed()).isZero();
        assertThat(storedSource.continuation().requestBytesWithheld()).isEqualTo(128);
        assertThat(storedSource.continuation().toString()).doesNotContain("recovery-1");
        assertThat(new RecordReader(jdbcOnExisting(tmp.resolve("linked.db")))
                .allOrderedBySeq().getFirst().hashable().toString())
                .doesNotContain("recovery-1");

        TurnRecord derived = new TurnRecord(derivedTurn("derived-1"),
                ContinuationEvidence.derived("recovery-1", "source-1"), complete(96));
        repository.append(derived);

        TurnRecord storedDerived = repository.findRecordById("derived-1").orElseThrow();
        assertThat(storedDerived.continuation().role()).isEqualTo(ContinuationEvidence.Role.DERIVED);
        assertThat(storedDerived.continuation().parentTurnId()).isEqualTo("source-1");
        assertThat(storedDerived.turn().action()).isEqualTo(Action.FLAG);
        assertThat(storedDerived.turn().requestBytesInspected()).isEqualTo(96);
        assertThat(storedDerived.turn().requestBytesEgressed()).isEqualTo(96);
    }

    @Test
    void v4ChainDetectsContinuationByteAndEdmAccountingEdits(@TempDir Path tmp) {
        assertV4TamperBreaks(tmp.resolve("v4-byte-tamper.db"),
                "UPDATE turns SET request_bytes_withheld = 127 WHERE turn_id = 'source-1'");
        assertV4TamperBreaks(tmp.resolve("v4-link-tamper.db"),
                "UPDATE turns SET recovery_id = 'different-recovery' WHERE turn_id = 'source-1'");
        assertV4TamperBreaks(tmp.resolve("v4-edm-tamper.db"),
                "UPDATE edm_events SET distinct_count = 2 WHERE turn_id = 'source-1'");
    }

    @Test
    void derivedRecordRequiresCommittedMatchingSource(@TempDir Path tmp) {
        TurnRepository repository = new TurnRepository(jdbcOn(tmp.resolve("parent-required.db")));

        assertThatThrownBy(() -> repository.append(new TurnRecord(derivedTurn("derived-1"),
                ContinuationEvidence.derived("recovery-1", "source-1"), complete(96))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("derived Record parent is missing");
        assertThat(repository.count()).isZero();
    }

    private static void assertV4TamperBreaks(Path db, String edit) {
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository repository = new TurnRepository(jdbc);
        repository.append(new TurnRecord(sourceTurn("source-1"), ContinuationEvidence.source(
                "recovery-1", "synthetic-email", 1, "repo-safe-edit", 1,
                "one-way", "eligible-edm", 128), complete(128)));

        assertThat(ChainVerifier.verify(new RecordReader(jdbc)).ok()).isTrue();

        jdbc.sql(edit).update();

        assertThat(ChainVerifier.verify(new RecordReader(jdbc)).ok()).isFalse();
    }

    private static NormalizedTurn sourceTurn(String id) {
        return new NormalizedTurn(id, "scope", "codex", "openai", "gpt-5-codex", null,
                "blocked", 0, 0, 0, 0, 0, 0, 0,
                List.of(new Finding("edm-customers", Action.BLOCK)), Action.BLOCK, 4,
                Instant.parse("2026-07-11T10:00:00Z"), "request-1", 128L, 128L, 0L,
                Map.of("customers", 1));
    }

    private static NormalizedTurn derivedTurn(String id) {
        return new NormalizedTurn(id, "scope", "codex", "openai", "gpt-5-codex",
                "gpt-5-codex", "completed", 10, 0, 10, 5, 0, 15, 0,
                List.of(), Action.FLAG, 8, Instant.parse("2026-07-11T10:00:01Z"),
                "request-1", 96L, 96L, 96L, Map.of());
    }

    private static JdbcClient jdbcOn(Path dbFile) {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + dbFile);
        applySchema(dataSource);
        return JdbcClient.create(dataSource);
    }

    private static JdbcClient jdbcOnExisting(Path dbFile) {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + dbFile);
        return JdbcClient.create(dataSource);
    }

    private static void applySchema(DataSource dataSource) {
        try (var in = TurnRepositoryContinuationTest.class.getResourceAsStream("/schema.sql");
             var connection = dataSource.getConnection();
             var statement = connection.createStatement()) {
            String schema = new String(in.readAllBytes());
            for (String sql : schema.split(";")) {
                if (!sql.isBlank()) {
                    statement.execute(sql);
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
