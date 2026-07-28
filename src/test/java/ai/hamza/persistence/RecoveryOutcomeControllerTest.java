package ai.hamza.persistence;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import ai.hamza.masking.MaskContinuationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.sqlite.SQLiteDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static ai.hamza.policy.DetectorEvidenceFixtures.complete;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RecoveryOutcomeControllerTest {

    private static final byte[] KEY =
            "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    private static final String RECOVERY_ID = "recovery-00000001";

    @Test
    void signedTerminalOutcomeAppendsAndErasesVolatileRecoveryState(@TempDir Path tmp)
            throws Exception {
        JdbcClient jdbc = jdbcOn(tmp.resolve("controller.db"));
        appendLinkedTurns(jdbc);
        RecoveryOutcomeAuthenticator authenticator = new RecoveryOutcomeAuthenticator(KEY);
        RecoveryOutcomeRepository repository = new RecoveryOutcomeRepository(jdbc, authenticator);
        MaskContinuationService maskContinuation = mock(MaskContinuationService.class);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(
                new RecoveryOutcomeController(repository, maskContinuation)).build();
        RecoveryOutcome signed = authenticator.sign(unsigned(RecoveryOutcome.Status.COMPLETED));

        mvc.perform(post("/admin/recovery-outcomes")
                        .contentType("application/json")
                        .content(json(signed)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.disposition").value("appended"))
                .andExpect(jsonPath("$.sequence").value(1));

        assertThat(repository.find(RECOVERY_ID)).contains(signed);
        verify(maskContinuation).closeScope(RECOVERY_ID);
    }

    private static String json(RecoveryOutcome outcome) throws Exception {
        RecoveryOutcome.Unsigned e = outcome.evidence();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("recoveryId", e.recoveryId());
        body.put("status", e.status().wireValue());
        body.put("agent", e.agent());
        body.put("agentVersion", e.agentVersion());
        body.put("workflowProfileId", e.workflowProfileId());
        body.put("workflowProfileVersion", e.workflowProfileVersion());
        body.put("acceptanceGateId", e.acceptanceGateId());
        body.put("startedAt", e.startedAt().toString());
        body.put("completedAt", e.completedAt().toString());
        body.put("signatureVersion", outcome.signatureVersion());
        body.put("signature", outcome.signature());
        return new ObjectMapper().writeValueAsString(body);
    }

    private static RecoveryOutcome.Unsigned unsigned(RecoveryOutcome.Status status) {
        return new RecoveryOutcome.Unsigned(RECOVERY_ID, status, "codex", "0.144.0",
                "repo-safe-edit", 1, "mvn-test",
                Instant.parse("2026-07-11T10:05:00Z"),
                Instant.parse("2026-07-11T10:06:00Z"));
    }

    private static void appendLinkedTurns(JdbcClient jdbc) {
        TurnRepository turns = new TurnRepository(jdbc);
        NormalizedTurn source = new NormalizedTurn("source-1", "scope", "codex", "openai",
                "gpt-5-codex", null, "blocked", 0, 0, 0, 0, 0, 0, 0,
                List.of(new Finding("edm-customers", Action.BLOCK)), Action.BLOCK, 4,
                Instant.parse("2026-07-11T10:00:00Z"), "request-1",
                128L, 128L, 0L, Map.of("customers", 1));
        NormalizedTurn derived = new NormalizedTurn("derived-1", "scope", "codex", "openai",
                "gpt-5-codex", "gpt-5-codex", "completed", 10, 0, 10, 5, 0, 15, 0,
                List.of(), Action.FLAG, 8, Instant.parse("2026-07-11T10:00:01Z"),
                "request-2", 96L, 96L, 96L, Map.of());
        turns.append(new TurnRecord(source, ContinuationEvidence.source(
                RECOVERY_ID, "synthetic-email", 1, "repo-safe-edit", 1,
                "one-way", "eligible-edm", 128), complete(128)));
        turns.append(new TurnRecord(derived,
                ContinuationEvidence.derived(RECOVERY_ID, "source-1"), complete(96)));
    }

    private static JdbcClient jdbcOn(Path dbFile) {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + dbFile);
        applySchema(dataSource);
        return JdbcClient.create(dataSource);
    }

    private static void applySchema(DataSource dataSource) {
        try (var in = RecoveryOutcomeControllerTest.class.getResourceAsStream("/schema.sql");
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
