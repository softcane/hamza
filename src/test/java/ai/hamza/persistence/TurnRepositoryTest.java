package ai.hamza.persistence;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.adapter.OpenAiResponsesAdapter;
import ai.hamza.adapter.RequestView;
import ai.hamza.adapter.TurnDraft;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M2 exit condition: a recorded fixture Turn is parsed and stored with correct token
 * math (cached ⊆ input; reasoning ⊆ output; total = input + output), then read back
 * unchanged.
 */
class TurnRepositoryTest {

    private static JdbcClient jdbcClientOn(Path dbFile) {
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + dbFile);
        applySchema(ds);
        return JdbcClient.create(ds);
    }

    private static void applySchema(DataSource ds) {
        String schema;
        try (var in = TurnRepositoryTest.class.getResourceAsStream("/schema.sql")) {
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

    private static byte[] completedFixture() {
        try (var in = TurnRepositoryTest.class.getResourceAsStream("/fixtures/openai-responses-completed.sse")) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Test
    void storesAndReadsBackFixtureTurnWithCorrectTokenMath(@TempDir Path tmp) throws Exception {
        Path db = tmp.resolve("hamza-test.db");
        Files.deleteIfExists(db);
        TurnRepository repo = new TurnRepository(jdbcClientOn(db));

        OpenAiResponsesAdapter adapter = new OpenAiResponsesAdapter();
        TurnDraft draft = new TurnDraft("turn-xyz", "sess-1", "codex",
                new RequestView("gpt-5-codex", 0, 0, 0), 200, completedFixture(), 123L);
        NormalizedTurn turn = adapter.finalizeTurn(draft);

        assertThat(repo.count()).isZero();
        repo.save(turn);
        assertThat(repo.count()).isEqualTo(1);

        NormalizedTurn stored = repo.findById("turn-xyz").orElseThrow();
        assertThat(stored.provider()).isEqualTo("openai");
        assertThat(stored.requestedModel()).isEqualTo("gpt-5-codex");
        assertThat(stored.servedModel()).isEqualTo("gpt-5-codex");
        assertThat(stored.status()).isEqualTo("completed");

        // Token math survives the round trip.
        assertThat(stored.inputTokens()).isEqualTo(120);
        assertThat(stored.cachedInputTokens()).isEqualTo(20);
        assertThat(stored.uncachedInputTokens()).isEqualTo(100);
        assertThat(stored.outputTokens()).isEqualTo(80);
        assertThat(stored.reasoningTokens()).isEqualTo(30);
        assertThat(stored.totalTokens()).isEqualTo(200);
        assertThat(stored.cachedInputTokens()).isLessThanOrEqualTo(stored.inputTokens());
        assertThat(stored.reasoningTokens()).isLessThanOrEqualTo(stored.outputTokens());
        assertThat(stored.totalTokens()).isEqualTo(stored.inputTokens() + stored.outputTokens());
        assertThat(stored.durationMs()).isEqualTo(123L);
    }
}
