package ai.hamza.persistence;

import ai.hamza.HamzaApplication;
import ai.hamza.attest.RecordHasher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

class SchemaVersionContractTest {

    @Test
    void freshStoreDeclaresV2AndWritesV5Hashes(@TempDir Path temp) {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + temp.resolve("fresh.db"));
        JdbcClient jdbc = JdbcClient.create(dataSource);
        new TurnRepository(jdbc);

        assertThat(jdbc.sql("SELECT version FROM schema_metadata WHERE singleton = 1")
                .query(String.class).single()).isEqualTo("hamza-db/v2");
        assertThat(TurnRepository.SCHEMA_VERSION).isEqualTo("hamza-db/v2");
        assertThat(RecordHasher.CURRENT_RECORD_VERSION).isEqualTo("hamza-record/v5");
    }

    @Test
    void legacyDatabaseIsRefusedWithoutMutation(@TempDir Path temp) throws Exception {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + temp.resolve("legacy.db"));
        JdbcClient jdbc = JdbcClient.create(dataSource);
        jdbc.sql("CREATE TABLE turns (turn_id TEXT PRIMARY KEY)").update();
        String before = jdbc.sql(
                        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'turns'")
                .query(String.class).single();

        assertThatThrownBy(() -> new TurnRepository(jdbc))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("legacy Hamza database refused")
                .hasMessageContaining("hamza-db/v2");

        assertThat(jdbc.sql(
                        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'turns'")
                .query(String.class).single()).isEqualTo(before);
        assertThat(jdbc.sql("SELECT COUNT(*) FROM sqlite_master WHERE name = 'schema_metadata'")
                .query(Long.class).single()).isZero();
    }

    @Test
    void realApplicationStartupRefusesLegacyDatabaseBeforeMutation(@TempDir Path temp) {
        Path path = temp.resolve("legacy-startup.db");
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + path);
        JdbcClient jdbc = JdbcClient.create(dataSource);
        jdbc.sql("CREATE TABLE turns (turn_id TEXT PRIMARY KEY)").update();
        String before = jdbc.sql(
                        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'turns'")
                .query(String.class).single();

        Throwable failure = catchThrowable(() -> new SpringApplicationBuilder(HamzaApplication.class)
                .run("--spring.datasource.url=jdbc:sqlite:" + path,
                        "--spring.grpc.server.port=0", "--server.port=0")
                .close());

        assertThat(rootCause(failure))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("legacy Hamza database refused")
                .hasMessageContaining("hamza-db/v2");
        assertThat(jdbc.sql(
                        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'turns'")
                .query(String.class).single()).isEqualTo(before);
        assertThat(jdbc.sql("SELECT COUNT(*) FROM sqlite_master WHERE name = 'schema_metadata'")
                .query(Long.class).single()).isZero();
    }

    @Test
    void v5HashCommitsToOrderedDetectorRunsAndQualifiedFindings() {
        var base = hashable(List.of(RecordHasher.detectorRunKey(
                "secret", "v1", "COMPLETE", null, 1, 1, 10, 10, 3, 1)));
        var changed = hashable(List.of(RecordHasher.detectorRunKey(
                "secret", "v1", "INCOMPLETE", "OUTPUT_LIMIT", 1, 0, 10, 0, 3, 1)));

        assertThat(RecordHasher.entryHash(RecordHasher.GENESIS, base))
                .isNotEqualTo(RecordHasher.entryHash(RecordHasher.GENESIS, changed));
        assertThat(base.findingKeys()).containsExactly(
                RecordHasher.findingKey("secret", "fake-rule", "MASK"));
    }

    private static RecordHasher.HashableTurn hashable(List<String> detectorRuns) {
        return new RecordHasher.HashableTurn(
                RecordHasher.CURRENT_RECORD_VERSION, "turn-1", "request-1", "scope-1",
                "codex", "openai", "gpt-5-codex", "gpt-5-codex", "completed",
                1, 0, 1, 1, 0, 2, 0, "MASK", 5, "2026-07-15T00:00:00Z",
                "MASK", "config", 10L, 10L, 10L,
                RecordHasher.ContinuationHashFields.none(), List.of(), detectorRuns,
                List.of(RecordHasher.findingKey("secret", "fake-rule", "MASK")));
    }

    private static Throwable rootCause(Throwable failure) {
        Throwable current = failure;
        while (current != null && current.getCause() != null) {
            current = current.getCause();
        }
        return current;
    }

    private static JdbcClient schema(Path path) throws Exception {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + path);
        String schema;
        try (var input = SchemaVersionContractTest.class.getResourceAsStream("/schema.sql")) {
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
