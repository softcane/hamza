package ai.hamza.policy;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.persistence.TurnRecord;
import ai.hamza.persistence.TurnRepository;
import ai.hamza.persistence.ContinuationEvidence;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DetectorEvidenceContractTest {

    @Test
    void detectionRunDeduplicatesExactFindingsAndProjectsContentFreeEvidence() {
        DetectionFinding finding = new DetectionFinding("fake-rule", Action.FLAG,
                "body", 2, 5, 0.99, true);
        DetectionRun run = new DetectionRun("secret", "fake-v1", DetectionStatus.COMPLETE,
                Optional.empty(), 1, 1, 8, 8, 12, List.of(finding, finding));

        assertThat(run.findings()).hasSize(1);
        assertThat(run.evidence().findingCount()).isEqualTo(1);
        assertThat(List.of(DetectorRunEvidence.class.getRecordComponents())
                .stream().map(java.lang.reflect.RecordComponent::getName))
                .doesNotContain("matchedText", "span", "start", "end", "score",
                        "placeholder", "mapping");
        assertThatThrownBy(() -> new DetectorRunEvidence(
                "unregistered", "v1", DetectionStatus.COMPLETE, Optional.empty(),
                1, 1, 1, 1, 1, 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("unknown detector id");
    }

    @Test
    void secretDetectorReportsUnicodeCodePointOffsets() {
        String text = "🙂 prefix AKIAABCDEFGHIJKLMNOP suffix";
        SecretDetector detector = new SecretDetector();
        List<SecretDetector.Match> matches = detector.detect(text);
        DetectionRun run = detector.run(text, matches, 1);
        SecretDetector.Match match = matches.getFirst();

        assertThat(run.findings().getFirst().start())
                .isEqualTo(text.codePointCount(0, match.start()));
        assertThat(run.findings().getFirst().end())
                .isEqualTo(text.codePointCount(0, match.end()));
    }

    @Test
    void durableDetectorEvidenceStoresNoSpanScoreOrContent(@TempDir Path temp) throws Exception {
        JdbcClient jdbc = schema(temp.resolve("evidence.db"));
        TurnRepository repository = new TurnRepository(jdbc);
        DetectorRunEvidence evidence = new DetectorRunEvidence(
                "secret", "fake-v1", DetectionStatus.COMPLETE, Optional.empty(),
                1, 1, 64, 64, 20, 1);
        Finding finding = new Finding("secret", "fake-rule", Action.MASK);
        NormalizedTurn turn = new NormalizedTurn("turn-1", "scope", "codex", "openai",
                "gpt-5-codex", "gpt-5-codex", "completed", 1, 0, 1, 1, 0, 2, 0,
                List.of(finding), Action.MASK, 5, Instant.parse("2026-07-15T00:00:00Z"));

        repository.append(TurnRecord.standard(turn, List.of(evidence)));

        assertThat(repository.findRecordById("turn-1").orElseThrow().detectorRuns())
                .containsExactly(evidence);
        assertThat(jdbc.sql("PRAGMA table_info(detector_runs)")
                .query((rs, n) -> rs.getString("name")).list())
                .doesNotContain("matched_text", "start", "end", "score", "placeholder",
                        "mapping", "raw_response");
        assertThat(jdbc.sql("SELECT detector FROM findings WHERE turn_id = 'turn-1'")
                .query(String.class).single()).isEqualTo("secret");
    }

    @Test
    void continuationRecordsRequireEveryRegisteredDetectorRun() {
        NormalizedTurn source = NormalizedTurn.blocked(
                "source-1", "request-1", "scope", "codex", "openai", "gpt-5-codex",
                List.of(new Finding("scan-incomplete", Action.BLOCK)), 1L,
                0L, 0L, 0L, Map.of());
        ContinuationEvidence continuation = ContinuationEvidence.source(
                "recovery-1", "recipe", 1, "profile", 1,
                "one-way", "source-scan-incomplete", 0L);
        DetectorRunEvidence secret = new DetectorRunEvidence(
                "secret", "fake-v1", DetectionStatus.SKIPPED,
                Optional.of(DetectionReason.UPSTREAM_BLOCK), 1, 0, 0, 0, 0, 0);

        assertThatThrownBy(() -> new TurnRecord(source, continuation))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("one run per registered detector");
        assertThatThrownBy(() -> new TurnRecord(source, continuation, List.of(secret)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("one run per registered detector");
    }

    private static JdbcClient schema(Path path) throws Exception {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + path);
        String schema;
        try (var input = DetectorEvidenceContractTest.class.getResourceAsStream("/schema.sql")) {
            schema = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            for (String sql : schema.split(";")) {
                if (!sql.isBlank()) {
                    statement.execute(sql);
                }
            }
        }
        return JdbcClient.create(dataSource);
    }
}
