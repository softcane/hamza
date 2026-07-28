package ai.hamza.attest;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.persistence.ContinuationEvidence;
import ai.hamza.persistence.RecoveryOutcome;
import ai.hamza.persistence.RecoveryOutcomeAuthenticator;
import ai.hamza.persistence.RecoveryOutcomeRepository;
import ai.hamza.persistence.TurnRecord;
import ai.hamza.persistence.TurnRepository;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static ai.hamza.policy.DetectorEvidenceFixtures.complete;

/**
 * Report JSON shape and the UNVERIFIED-coverage refusal path: with no
 * access-log feed the report must say "coverage: UNVERIFIED" and refuse a percentage.
 */
class AttestationReporterTest {

    private static JdbcClient jdbcOn(Path dbFile) {
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + dbFile);
        applySchema(ds);
        return JdbcClient.create(ds);
    }

    private static void applySchema(DataSource ds) {
        String schema;
        try (var in = AttestationReporterTest.class.getResourceAsStream("/schema.sql")) {
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

    private static NormalizedTurn turn(String id, String tsSuffix, List<Finding> findings, Action action) {
        Map<String, Integer> edmCounts = findings.stream().anyMatch(f -> f.rule().equals("edm-customers"))
                ? Map.of("customers", 12) : Map.of();
        return new NormalizedTurn(id, "sess", "codex", "openai", "gpt-5-codex", "gpt-5-codex",
                "completed", 100, 0, 100, 10, 0, 110, 0, findings, action, 5L,
                Instant.parse("2026-07-06T10:0" + tsSuffix + ":00Z"),
                "rid-" + id, 20L, 20L, action == Action.BLOCK ? 0L : 20L, edmCounts);
    }

    private static TurnRepository seed(JdbcClient jdbc) {
        TurnRepository repo = new TurnRepository(jdbc, "MASK", "cfg-fp-123");
        repo.save(turn("t1", "0", List.of(new Finding("aws-access-key-id", Action.MASK)), Action.MASK));
        repo.save(turn("t2", "1", List.of(new Finding("edm-customers", Action.BLOCK)), Action.BLOCK));
        return repo;
    }

    private static ReportModel model(JdbcClient jdbc, ReportModel.Coverage coverage) {
        RecordReader reader = new RecordReader(jdbc);
        return ReportModel.build(Instant.now().toString(),
                "2026-07-06T00:00:00Z", "2026-07-07T00:00:00Z",
                reader.inWindow("2026-07-06T00:00:00Z", "2026-07-07T00:00:00Z"),
                ChainVerifier.verify(reader), coverage);
    }

    @Test
    void jsonShapeCoversTheR41LineItems(@TempDir Path tmp) throws Exception {
        JdbcClient jdbc = jdbcOn(tmp.resolve("report.db"));
        seed(jdbc);
        ReportModel m = model(jdbc, ReportModel.Coverage.unverified(2));

        JsonNode json = new ObjectMapper().readTree(AttestationReporter.toJson(m));
        assertThat(json.get("schema").asText()).isEqualTo("hamza-attestation/v2");
        assertThat(json.get("turns_seen").asLong()).isEqualTo(2);
        assertThat(json.get("blocks").asLong()).isEqualTo(1);
        assertThat(json.get("findings_by_rule").get("aws-access-key-id").asLong()).isEqualTo(1);
        assertThat(json.get("findings_by_rule").get("edm-customers").asLong()).isEqualTo(1);
        assertThat(json.get("findings_by_action").get("MASK").asLong()).isEqualTo(1);
        assertThat(json.get("findings_by_action").get("BLOCK").asLong()).isEqualTo(1);
        assertThat(json.get("postures").get("MASK").asLong()).isEqualTo(2);
        assertThat(json.get("config_fingerprints").get("cfg-fp-123").asLong()).isEqualTo(2);
        assertThat(json.get("chain").get("status").asText()).isEqualTo("OK");
        assertThat(json.get("chain").get("entries").asLong()).isEqualTo(2);
        assertThat(json.get("inspected_bytes").get("status").asText()).isEqualTo("UNVERIFIED");
        assertThat(json.get("edm_events").get("customers").get("distinct_matches").asLong()).isEqualTo(12);
        assertThat(json.get("registry_staleness").get("status").asText()).isEqualTo("UNVERIFIED");
        assertThat(json.get("covered_population").asText()).isEqualTo("UNVERIFIED");
        assertThat(json.get("safe_continuation").get("attempted").asLong()).isZero();
    }

    @Test
    void withoutAnAccessLogCoverageIsUnverified(@TempDir Path tmp) throws Exception {
        JdbcClient jdbc = jdbcOn(tmp.resolve("unverified.db"));
        seed(jdbc);
        ReportModel m = model(jdbc, ReportModel.Coverage.unverified(2));

        JsonNode coverage = new ObjectMapper().readTree(AttestationReporter.toJson(m)).get("coverage");
        assertThat(coverage.get("status").asText()).isEqualTo("UNVERIFIED");
        assertThat(coverage.get("coverage_percent").isNull()).isTrue();
        assertThat(coverage.get("envoy_provider_requests").isNull()).isTrue();

        // The HTML surfaces the refusal too.
        assertThat(AttestationReporter.toHtml(m)).contains("coverage: UNVERIFIED");
    }

    @Test
    void anyLedgerGapMakesCoverageUnverified(@TempDir Path tmp) throws Exception {
        JdbcClient jdbc = jdbcOn(tmp.resolve("verified.db"));
        seed(jdbc);

        String log = String.join("\n",
                "{\"log\":\"access\",\"start_time\":\"2026-07-06T10:00:30.000Z\",\"method\":\"POST\","
                        + "\"path\":\"/v1/responses\",\"response_code\":200,"
                        + "\"upstream_cluster\":\"provider_upstream\",\"request_id\":\"rid-t1\","
                        + "\"bytes_received\":\"20\",\"bytes_sent\":\"10\"}",
                "{\"log\":\"access\",\"start_time\":\"2026-07-06T10:01:30.000Z\",\"method\":\"POST\","
                        + "\"path\":\"/v1/responses\",\"response_code\":403,"
                        + "\"upstream_cluster\":\"provider_upstream\",\"request_id\":\"rid-gap\","
                        + "\"bytes_received\":\"10\",\"bytes_sent\":\"10\"}");
        var entries = AccessLogReconciler.parse(log);
        var flows = List.of(
                new FlowFeedReconciler.FlowEntry("2026-07-06T10:00:30Z", "api.openai.com",
                        "", "FORWARDED", 20),
                new FlowFeedReconciler.FlowEntry("2026-07-06T10:01:30Z", "api.openai.com",
                        "", "FORWARDED", 20));
        var recon = AccessLogReconciler.reconcile(entries,
                new RecordReader(jdbc).inWindow("2026-07-06T00:00:00Z", "2026-07-07T00:00:00Z"),
                flows, Set.of("api.openai.com"),
                "2026-07-06T00:00:00Z", "2026-07-07T00:00:00Z");
        ReportModel.Coverage coverage = ReportModel.Coverage.verified(recon);
        ReportModel m = ReportModel.build(Instant.now().toString(),
                "2026-07-06T00:00:00Z", "2026-07-07T00:00:00Z",
                new RecordReader(jdbc).inWindow("2026-07-06T00:00:00Z", "2026-07-07T00:00:00Z"),
                ChainVerifier.verify(new RecordReader(jdbc)), coverage,
                ReportModel.ByteInspection.fromCoverage(coverage, recon),
                ReportModel.RegistryStaleness.unverified("not supplied"),
                "covered test population");

        JsonNode coverageJson = new ObjectMapper().readTree(AttestationReporter.toJson(m)).get("coverage");
        assertThat(coverageJson.get("status").asText()).isEqualTo("UNVERIFIED");
        assertThat(coverageJson.get("envoy_provider_requests").asLong()).isEqualTo(2);
        assertThat(coverageJson.get("flow_bytes").asLong()).isEqualTo(40);
        assertThat(coverageJson.get("coverage_gaps").asLong()).isEqualTo(1);
        assertThat(coverageJson.get("fail_open_uninspected_minutes").asLong()).isEqualTo(1);
        assertThat(coverageJson.get("coverage_percent").isNull()).isTrue();
        JsonNode bytes = new ObjectMapper().readTree(AttestationReporter.toJson(m)).get("inspected_bytes");
        assertThat(bytes.get("status").asText()).isEqualTo("UNVERIFIED");
        assertThat(bytes.get("inspected_percent").isNull()).isTrue();
    }

    @Test
    void registryStalenessDoesNotInventVerifiedAgeFromFileMtime(@TempDir Path tmp) throws Exception {
        JdbcClient jdbc = jdbcOn(tmp.resolve("registry.db"));
        seed(jdbc);
        Path registryDir = tmp.resolve("edm");
        Files.createDirectories(registryDir);
        Files.writeString(registryDir.resolve("customers.json"),
                "{\"registry\":\"customers\",\"fingerprints\":[\"abc\",\"def\"]}");
        Path outJson = tmp.resolve("attestation.json");
        Path outHtml = tmp.resolve("attestation.html");

        AttestationReporter.main(new String[]{
                "--db", tmp.resolve("registry.db").toString(),
                "--out-json", outJson.toString(),
                "--out-html", outHtml.toString(),
                "--edm-registry-dir", registryDir.toString()
        });

        JsonNode staleness = new ObjectMapper().readTree(Files.readString(outJson))
                .get("registry_staleness");
        assertThat(staleness.get("status").asText()).isEqualTo("UNVERIFIED");
        assertThat(staleness.get("note").asText()).contains("push/index timestamp");
        JsonNode registry = staleness.get("registries").get(0);
        assertThat(registry.get("registry").asText()).isEqualTo("customers");
        assertThat(registry.get("distinctFingerprints").asLong()).isEqualTo(2);
        assertThat(registry.get("ageSeconds").isNull()).isTrue();
        assertThat(registry.get("sourceTimestamp").asText()).isNotBlank();
    }

    @Test
    void standaloneReporterVerifiesAndAccountsForRecoveryOutcome(@TempDir Path tmp)
            throws Exception {
        Path db = tmp.resolve("continuation.db");
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository turns = new TurnRepository(jdbc);
        turns.append(new TurnRecord(sourceTurn(), ContinuationEvidence.source(
                "recovery-1", "synthetic-email", 1, "repo-safe-edit", 1,
                "one-way", "eligible-edm", 128), complete(128)));
        turns.append(new TurnRecord(derivedTurn(),
                ContinuationEvidence.derived("recovery-1", "source-1"), complete(96)));
        byte[] key = "0123456789abcdef0123456789abcdef"
                .getBytes(StandardCharsets.US_ASCII);
        RecoveryOutcomeAuthenticator authenticator = new RecoveryOutcomeAuthenticator(key);
        new RecoveryOutcomeRepository(jdbc, authenticator).append(authenticator.sign(
                new RecoveryOutcome.Unsigned("recovery-1", RecoveryOutcome.Status.COMPLETED,
                        "codex", "0.144.0", "repo-safe-edit", 1, "mvn-test",
                        Instant.parse("2026-07-11T10:05:00Z"),
                        Instant.parse("2026-07-11T10:06:00Z"))));
        Path outJson = tmp.resolve("continuation-attestation.json");
        Path outHtml = tmp.resolve("continuation-attestation.html");
        Path signingKey = tmp.resolve("outcome-signing.key");
        Files.write(signingKey, key);

        AttestationReporter.main(new String[]{
                "--db", db.toString(), "--out-json", outJson.toString(),
                "--out-html", outHtml.toString(), "--outcome-signing-key-file",
                signingKey.toString()
        });

        String reportText = Files.readString(outJson);
        JsonNode continuation = new ObjectMapper().readTree(reportText).get("safe_continuation");
        assertThat(continuation.get("attempted").asLong()).isEqualTo(1);
        assertThat(continuation.get("delivered").asLong()).isEqualTo(1);
        assertThat(continuation.get("completed").asLong()).isEqualTo(1);
        assertThat(continuation.get("outcome_integrity").get("status").asText())
                .isEqualTo("OK");
        assertThat(reportText).doesNotContain("recovery-1", "source-1", "derived-1",
                "mvn-test", "alice@example-corp.test",
                "hamza-0123456789abcdef0123456789abcdef@example.invalid");
    }

    @Test
    void brokenChainCannotCopyTamperedContentIntoEvidence(@TempDir Path tmp) throws Exception {
        JdbcClient jdbc = jdbcOn(tmp.resolve("tampered-report.db"));
        seed(jdbc);
        String planted = "alice@example-corp.test";
        ChainVerifier.Result broken = new ChainVerifier.Result(false, 2, 1,
                "prev_hash mismatch: row carries " + planted, planted, 0);
        List<RecordRow> rows = new RecordReader(jdbc).inWindow(
                "2026-07-06T00:00:00Z", "2026-07-07T00:00:00Z");
        ReportModel report = ReportModel.build(Instant.now().toString(),
                "2026-07-06T00:00:00Z", "2026-07-07T00:00:00Z", rows, broken,
                ReportModel.Coverage.unverified(rows.size()));

        String json = AttestationReporter.toJson(report);
        String html = AttestationReporter.toHtml(report);
        assertThat(json).doesNotContain(planted);
        assertThat(html).doesNotContain(planted);
        assertThat(new ObjectMapper().readTree(json).get("safe_continuation")
                .get("coverage_gaps").get("turn-record-integrity-invalid").asLong())
                .isEqualTo(1);
    }

    private static NormalizedTurn sourceTurn() {
        return new NormalizedTurn("source-1", "scope", "codex", "openai",
                "gpt-5-codex", null, "blocked", 0, 0, 0, 0, 0, 0, 0,
                List.of(new Finding("edm-customers", Action.BLOCK)), Action.BLOCK, 4,
                Instant.parse("2026-07-11T10:00:00Z"), "request-source",
                128L, 128L, 0L, Map.of("customers", 1));
    }

    private static NormalizedTurn derivedTurn() {
        return new NormalizedTurn("derived-1", "scope", "codex", "openai",
                "gpt-5-codex", "gpt-5-codex", "completed", 10, 0, 10, 5, 0,
                15, 0, List.of(), Action.FLAG, 8,
                Instant.parse("2026-07-11T10:00:01Z"), "request-derived",
                96L, 96L, 96L, Map.of());
    }
}
