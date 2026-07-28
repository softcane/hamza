package ai.hamza.persistence;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.attest.RecoveryOutcomeChainVerifier;
import ai.hamza.attest.RecoveryOutcomeReader;
import ai.hamza.attest.RecordHasher;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static ai.hamza.policy.DetectorEvidenceFixtures.complete;

class RecoveryOutcomeRepositoryTest {

    private static final byte[] SIGNING_KEY =
            "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);

    @Test
    void appendsVerifiedOutcomeWithoutMutatingLinkedTurns(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("outcome.db"));
        appendLinkedTurns(jdbc, "recovery-1");
        RecoveryOutcomeAuthenticator authenticator = new RecoveryOutcomeAuthenticator(SIGNING_KEY);
        RecoveryOutcomeRepository repository = new RecoveryOutcomeRepository(jdbc, authenticator);
        RecoveryOutcome outcome = authenticator.sign(unsigned("recovery-1",
                RecoveryOutcome.Status.COMPLETED));

        Map<String, String> turnHashesBefore = turnHashes(jdbc);
        RecoveryOutcomeAppendReceipt receipt = repository.append(outcome);

        assertThat(receipt.disposition()).isEqualTo(
                RecoveryOutcomeAppendReceipt.Disposition.APPENDED);
        assertThat(receipt.entryHash()).hasSize(64);
        assertThat(turnHashes(jdbc)).isEqualTo(turnHashesBefore);
        assertThat(repository.find("recovery-1")).contains(outcome);
        assertThat(RecoveryOutcomeChainVerifier.verify(
                new RecoveryOutcomeReader(jdbc), authenticator).ok()).isTrue();
    }

    @Test
    void identicalReplayIsIdempotentAndConflictingTerminalOutcomeCreatesIntegrityGap(
            @TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("replay.db"));
        appendLinkedTurns(jdbc, "recovery-1");
        RecoveryOutcomeAuthenticator authenticator = new RecoveryOutcomeAuthenticator(SIGNING_KEY);
        RecoveryOutcomeRepository repository = new RecoveryOutcomeRepository(jdbc, authenticator);
        RecoveryOutcome completed = authenticator.sign(unsigned("recovery-1",
                RecoveryOutcome.Status.COMPLETED));

        repository.append(completed);
        RecoveryOutcomeAppendReceipt replay = repository.append(completed);
        RecoveryOutcomeAppendReceipt conflict = repository.append(authenticator.sign(
                unsigned("recovery-1", RecoveryOutcome.Status.FAILED)));

        assertThat(replay.disposition()).isEqualTo(
                RecoveryOutcomeAppendReceipt.Disposition.IDEMPOTENT_REPLAY);
        assertThat(conflict.disposition()).isEqualTo(
                RecoveryOutcomeAppendReceipt.Disposition.CONFLICT_REJECTED);
        assertThat(jdbc.sql("SELECT COUNT(*) FROM recovery_outcomes")
                .query(Long.class).single()).isEqualTo(1);
        assertThat(repository.find("recovery-1")).contains(completed);
        assertThat(repository.integrityGapCount()).isEqualTo(1);
        RecoveryOutcomeChainVerifier.Result evidence = RecoveryOutcomeChainVerifier.verify(
                new RecoveryOutcomeReader(jdbc), authenticator);
        assertThat(evidence.ok()).isFalse();
        assertThat(evidence.integrityGaps()).isEqualTo(1);
    }

    @Test
    void rejectsUnsignedOrUnlinkedOutcomeEvidence(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("rejected.db"));
        RecoveryOutcomeAuthenticator authenticator = new RecoveryOutcomeAuthenticator(SIGNING_KEY);
        RecoveryOutcomeRepository repository = new RecoveryOutcomeRepository(jdbc, authenticator);
        RecoveryOutcome validButUnlinked = authenticator.sign(unsigned("recovery-missing",
                RecoveryOutcome.Status.FAILED));
        RecoveryOutcome forged = new RecoveryOutcome(validButUnlinked.evidence(),
                validButUnlinked.signatureVersion(), "0".repeat(64));

        assertThatThrownBy(() -> repository.append(forged))
                .isInstanceOf(RecoveryOutcomeRejectedException.class)
                .extracting(error -> ((RecoveryOutcomeRejectedException) error).reason())
                .isEqualTo(RecoveryOutcomeRejectedException.Reason.INVALID_SIGNATURE);
        assertThatThrownBy(() -> repository.append(validButUnlinked))
                .isInstanceOf(RecoveryOutcomeRejectedException.class)
                .extracting(error -> ((RecoveryOutcomeRejectedException) error).reason())
                .isEqualTo(RecoveryOutcomeRejectedException.Reason.MISSING_LINKED_TURNS);
        assertThat(jdbc.sql("SELECT COUNT(*) FROM recovery_outcomes")
                .query(Long.class).single()).isZero();
    }

    @Test
    void validatesEveryDerivedParentBeforeAcceptingOutcome(@TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("parent.db"));
        appendLinkedTurns(jdbc, "recovery-1");
        jdbc.sql("UPDATE turns SET parent_turn_id = 'not-the-source' WHERE record_role = 'DERIVED'")
                .update();
        RecoveryOutcomeAuthenticator authenticator = new RecoveryOutcomeAuthenticator(SIGNING_KEY);
        RecoveryOutcomeRepository repository = new RecoveryOutcomeRepository(jdbc, authenticator);

        assertThatThrownBy(() -> repository.append(authenticator.sign(unsigned(
                "recovery-1", RecoveryOutcome.Status.COMPLETED))))
                .isInstanceOf(RecoveryOutcomeRejectedException.class)
                .extracting(error -> ((RecoveryOutcomeRejectedException) error).reason())
                .isEqualTo(RecoveryOutcomeRejectedException.Reason.INVALID_PARENT_LINK);
    }

    @Test
    void signedChainDetectsAnEditedOutcomeEvenWhenItsPlainHashIsRecomputed(
            @TempDir Path tmp) {
        JdbcClient jdbc = jdbcOn(tmp.resolve("tamper.db"));
        appendLinkedTurns(jdbc, "recovery-1");
        RecoveryOutcomeAuthenticator authenticator = new RecoveryOutcomeAuthenticator(SIGNING_KEY);
        RecoveryOutcomeRepository repository = new RecoveryOutcomeRepository(jdbc, authenticator);
        repository.append(authenticator.sign(unsigned("recovery-1",
                RecoveryOutcome.Status.COMPLETED)));

        jdbc.sql("UPDATE recovery_outcomes SET outcome_status = 'failed'").update();
        var edited = new RecoveryOutcomeReader(jdbc).allOrderedBySeq().getFirst();
        String attackerRecomputedHash = RecordHasher.recoveryOutcomeEntryHash(
                edited.prevHash(), edited.hashable());
        jdbc.sql("UPDATE recovery_outcomes SET entry_hash = ?")
                .param(attackerRecomputedHash).update();

        RecoveryOutcomeChainVerifier.Result result = RecoveryOutcomeChainVerifier.verify(
                new RecoveryOutcomeReader(jdbc), authenticator);
        assertThat(result.ok()).isFalse();
        assertThat(result.detail()).isEqualTo("signature mismatch");
    }

    @Test
    void durableOutcomeEvidenceAndSafeStringFormsAreContentFree(@TempDir Path tmp)
            throws IOException {
        Path db = tmp.resolve("content-free.db");
        JdbcClient jdbc = jdbcOn(db);
        appendLinkedTurns(jdbc, "recovery-1");
        RecoveryOutcomeAuthenticator authenticator = new RecoveryOutcomeAuthenticator(SIGNING_KEY);
        RecoveryOutcome outcome = authenticator.sign(unsigned("recovery-1",
                RecoveryOutcome.Status.HUMAN_FALLBACK));
        new RecoveryOutcomeRepository(jdbc, authenticator).append(outcome);

        List<String> columns = jdbc.sql("PRAGMA table_info(recovery_outcomes)")
                .query((rs, n) -> rs.getString("name")).list();
        assertThat(columns).noneMatch(name -> name.contains("body")
                || name.contains("fingerprint") || name.contains("substitute")
                || name.contains("mapping") || name.contains("field_id")
                || name.contains("authorization"));
        assertThat(outcome.toString())
                .doesNotContain("recovery-1", outcome.signature());
        var durableRow = new RecoveryOutcomeReader(jdbc).allOrderedBySeq().getFirst();
        assertThat(durableRow.toString()).doesNotContain("recovery-1", outcome.signature());
        assertThat(durableRow.hashable().toString())
                .doesNotContain("recovery-1", outcome.signature());

        String durableBytes = new String(Files.readAllBytes(db), StandardCharsets.ISO_8859_1);
        assertThat(durableBytes).doesNotContain(
                "alice@example-corp.test",
                "hamza-0123456789abcdef0123456789abcdef@example.invalid",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    }

    private static RecoveryOutcome.Unsigned unsigned(String recoveryId,
                                                      RecoveryOutcome.Status status) {
        return new RecoveryOutcome.Unsigned(recoveryId, status, "codex", "0.144.0",
                "repo-safe-edit", 1, "mvn-test", Instant.parse("2026-07-11T10:05:00Z"),
                Instant.parse("2026-07-11T10:06:00Z"));
    }

    private static void appendLinkedTurns(JdbcClient jdbc, String recoveryId) {
        TurnRepository turns = new TurnRepository(jdbc);
        turns.append(new TurnRecord(sourceTurn("source-1"), ContinuationEvidence.source(
                recoveryId, "synthetic-email", 1, "repo-safe-edit", 1,
                "one-way", "eligible-edm", 128), complete(128)));
        turns.append(new TurnRecord(derivedTurn("derived-1"),
                ContinuationEvidence.derived(recoveryId, "source-1"), complete(96)));
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

    private static Map<String, String> turnHashes(JdbcClient jdbc) {
        return jdbc.sql("SELECT turn_id, entry_hash FROM turns ORDER BY seq")
                .query((rs, n) -> Map.entry(rs.getString(1), rs.getString(2))).list()
                .stream().collect(java.util.stream.Collectors.toMap(Map.Entry::getKey,
                        Map.Entry::getValue));
    }

    private static JdbcClient jdbcOn(Path dbFile) {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + dbFile);
        applySchema(dataSource);
        return JdbcClient.create(dataSource);
    }

    private static void applySchema(DataSource dataSource) {
        try (var in = RecoveryOutcomeRepositoryTest.class.getResourceAsStream("/schema.sql");
             var connection = dataSource.getConnection();
             var statement = connection.createStatement()) {
            String schema = new String(in.readAllBytes(), StandardCharsets.UTF_8);
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
