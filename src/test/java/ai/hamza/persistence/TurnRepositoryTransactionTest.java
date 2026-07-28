package ai.hamza.persistence;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static ai.hamza.policy.DetectorEvidenceFixtures.complete;

/**
 * The Spring-wired save path commits a Turn and its Findings in ONE transaction (second
 * pass on): the entry_hash commits to the finding keys, so a torn write (turn
 * row present, findings missing) would make the chain verifier report tampering for what
 * was only a crash. A failing findings insert must roll the whole Turn back.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite:${java.io.tmpdir}/hamza-tx-test-${random.uuid}.db",
        "spring.grpc.server.port=0",
        "server.port=0"
})
class TurnRepositoryTransactionTest {

    @Autowired
    private TurnRepository repository;

    @Autowired
    private JdbcClient jdbc;

    private static NormalizedTurn turn(String id, List<Finding> findings) {
        return new NormalizedTurn(id, "sess", "codex", "openai", "gpt-5-codex",
                "gpt-5-codex", "completed", 10, 0, 10, 5, 0, 15, 0, findings,
                Action.FLAG, 5L, Instant.parse("2026-07-06T10:00:00Z"));
    }

    @Test
    void failedFindingInsertRollsBackTheWholeTurn() {
        long before = repository.count();

        installForcedFindingFailure();
        try {
            // The trigger fails AFTER the turn row is inserted. Without one transaction,
            // this leaves a torn turn whose committed hash references a missing Finding.
            assertThatThrownBy(() -> repository.save(
                    turn("tx-torn", List.of(new Finding("forced-failure", Action.FLAG)))))
                    .isInstanceOf(Exception.class);
        } finally {
            removeForcedFindingFailure();
        }
        assertThat(repository.count()).as("torn turn row must be rolled back")
                .isEqualTo(before);

        // And the chain still appends cleanly afterwards.
        repository.save(turn("tx-good-" + System.nanoTime(),
                List.of(new Finding("aws-access-key-id", Action.FLAG))));
        assertThat(repository.count()).isEqualTo(before + 1);
    }

    @Test
    void failedSourceRecordCommitLeavesNoParentForDerivedRelease() {
        long before = repository.count();
        NormalizedTurn source = new NormalizedTurn(
                "tx-source-" + System.nanoTime(), "scope", "codex", "openai",
                "gpt-5-codex", null, "blocked", 0, 0, 0, 0, 0, 0, 0,
                List.of(new Finding("forced-failure", Action.BLOCK)), Action.BLOCK, 5,
                Instant.parse("2026-07-11T10:00:00Z"), "request-source",
                64L, 64L, 0L, Map.of("customers", 1));
        TurnRecord sourceRecord = new TurnRecord(source, ContinuationEvidence.source(
                "recovery-source", "synthetic-email", 1, "repo-safe-edit", 1,
                "one-way", "eligible-edm", 64), complete(64));

        installForcedFindingFailure();
        try {
            assertThatThrownBy(() -> repository.append(sourceRecord)).isInstanceOf(Exception.class);
        } finally {
            removeForcedFindingFailure();
        }
        assertThat(repository.count()).isEqualTo(before);
        assertThatThrownBy(() -> repository.append(new TurnRecord(
                new NormalizedTurn("tx-derived-" + System.nanoTime(), "scope", "codex",
                        "openai", "gpt-5-codex", "gpt-5-codex", "completed",
                        1, 0, 1, 1, 0, 2, 0, List.of(), Action.FLAG, 5,
                        Instant.parse("2026-07-11T10:00:01Z"), "request-source",
                        32L, 32L, 32L, Map.of()),
                ContinuationEvidence.derived("recovery-source", source.turnId()), complete(32))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("derived Record parent is missing");
    }

    private void installForcedFindingFailure() {
        jdbc.sql("""
                CREATE TRIGGER fail_forced_finding
                BEFORE INSERT ON findings
                WHEN NEW.rule = 'forced-failure'
                BEGIN
                    SELECT RAISE(FAIL, 'forced finding insert failure');
                END
                """).update();
    }

    private void removeForcedFindingFailure() {
        jdbc.sql("DROP TRIGGER fail_forced_finding").update();
    }
}
