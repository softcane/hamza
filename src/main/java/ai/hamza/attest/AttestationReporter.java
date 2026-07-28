package ai.hamza.attest;

import ai.hamza.adapter.AdapterRegistry;
import ai.hamza.config.HamzaProperties;
import ai.hamza.persistence.RecoveryOutcomeAuthenticator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Generates the attestation Receipt: a content-free HTML +
 * JSON report over a time window covering turns seen, Findings by rule/Action, blocks,
 * posture, config fingerprint, the tamper-evident chain-verification result, and the
 * Envoy-vs-Record coverage reconciliation. With no access-log feed it prints
 * "coverage: UNVERIFIED" rather than implying full coverage.
 *
 * <p>Runs standalone from the fat jar via PropertiesLauncher — see
 * {@code scripts/attest-report.sh}. HTML is hand-rolled (no template library); JSON is
 * serialized with the Jackson already on the classpath.
 */
public final class AttestationReporter {

    private static final String MIN_TS = "0000-01-01T00:00:00Z";
    private static final String MAX_TS = "9999-12-31T23:59:59Z";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AttestationReporter() {
    }

    public static void main(String[] args) throws IOException {
        Map<String, String> opts = parseArgs(args);
        String db = opts.get("db");
        if (db == null) {
            System.err.println("usage: AttestationReporter --db <path> [--from <iso>] [--to <iso>] "
                    + "[--out-json <path>] [--out-html <path>] [--access-log <path>] "
                    + "[--flows <path>] [--edm-registry-dir <path>] [--covered-population <sentence>] "
                    + "[--outcome-signing-key-file <path>]");
            System.exit(2);
        }
        String from = opts.getOrDefault("from", MIN_TS);
        String to = opts.getOrDefault("to", MAX_TS);
        Path outJson = Path.of(opts.getOrDefault("out-json", "attestation.json"));
        Path outHtml = Path.of(opts.getOrDefault("out-html", "attestation.html"));
        String accessLog = opts.get("access-log");
        String flows = opts.get("flows");
        String registryDir = opts.get("edm-registry-dir");
        String coveredPopulation = opts.getOrDefault("covered-population",
                System.getenv().getOrDefault("HAMZA_ATTESTATION_COVERED_POPULATION",
                        HamzaProperties.DEFAULT_COVERED_POPULATION));

        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + db);
        JdbcClient jdbc = JdbcClient.create(ds);
        RecordReader reader = new RecordReader(jdbc);

        ChainVerifier.Result chain = ChainVerifier.verify(reader);
        List<RecordRow> allRows = reader.allOrderedBySeq();
        List<RecordRow> window = reader.inWindow(from, to);
        RecoveryOutcomeReader outcomeReader = new RecoveryOutcomeReader(jdbc);
        List<RecoveryOutcomeRow> outcomeRows = outcomeReader.allOrderedBySeq();
        RecoveryOutcomeChainVerifier.Result outcomeChain = verifyOutcomes(
                outcomeReader, opts.get("outcome-signing-key-file"));
        ContinuationAttestation.Summary continuation = ContinuationAttestation.evaluate(
                window, allRows, outcomeRows, outcomeChain,
                outcomeReader.integrityGapCount());

        Instant generatedAt = Instant.now();
        ReportModel.Coverage coverage;
        AccessLogReconciler.Reconciliation reconciliation = null;
        if (accessLog != null) {
            String raw = Files.readString(Path.of(accessLog), StandardCharsets.UTF_8);
            var entries = AccessLogReconciler.parse(raw);
            List<FlowFeedReconciler.FlowEntry> flowEntries = List.of();
            if (flows != null) {
                flowEntries = FlowFeedReconciler.parse(Files.readString(Path.of(flows), StandardCharsets.UTF_8));
            }
            reconciliation = AccessLogReconciler.reconcile(entries, window, flowEntries,
                    AdapterRegistry.providerDomains(), from, to);
            coverage = flows == null
                    ? ReportModel.Coverage.unverified(reconciliation)
                    : ReportModel.Coverage.verified(reconciliation);
        } else {
            coverage = ReportModel.Coverage.unverified(window.size());
        }
        ReportModel.ByteInspection inspectedBytes = ReportModel.ByteInspection
                .fromCoverage(coverage, reconciliation);
        ReportModel.RegistryStaleness staleness = registryDir == null || registryDir.isBlank()
                ? ReportModel.RegistryStaleness.unverified(
                        "No EDM registry directory supplied; staleness cannot be verified.")
                : registryStaleness(Path.of(registryDir));

        ReportModel model = ReportModel.build(generatedAt.toString(), from, to, window,
                chain, coverage, inspectedBytes, staleness, coveredPopulation, continuation);

        Files.writeString(outJson, toJson(model), StandardCharsets.UTF_8);
        Files.writeString(outHtml, AttestationReportRenderer.toHtml(model), StandardCharsets.UTF_8);

        System.out.printf("[attest] window=[%s,%s) turns=%d blocks=%d chain=%s coverage=%s%n",
                from, to, model.turnsSeen(), model.blocks(),
                chain.ok() ? "OK" : "BROKEN(seq=" + chain.firstBrokenSeq() + ")",
                model.coverage().status());
        System.out.printf("[attest] wrote %s and %s%n", outJson, outHtml);
    }

    private static RecoveryOutcomeChainVerifier.Result verifyOutcomes(
            RecoveryOutcomeReader reader, String keyFile) throws IOException {
        byte[] key = null;
        if (keyFile != null && !keyFile.isBlank()) {
            key = Files.readAllBytes(Path.of(keyFile));
        } else {
            String encoded = System.getenv("HAMZA_CONTINUATION_SIGNING_KEY_BASE64");
            if (encoded != null && !encoded.isBlank()) {
                try {
                    key = Base64.getDecoder().decode(encoded);
                } catch (IllegalArgumentException invalid) {
                    throw new IllegalArgumentException(
                            "invalid Recovery Outcome verification key", invalid);
                }
            }
        }
        if (key == null) {
            return null;
        }
        try {
            return RecoveryOutcomeChainVerifier.verify(reader,
                    new RecoveryOutcomeAuthenticator(key));
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException(
                    "invalid Recovery Outcome verification key", invalid);
        }
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> opts = new LinkedHashMap<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--") && i + 1 < args.length) {
                opts.put(a.substring(2), args[++i]);
            }
        }
        return opts;
    }

    // ---- JSON ----

    static String toJson(ReportModel m) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schema", m.schemaVersion());
        root.put("generated_at", m.generatedAt());
        Map<String, Object> window = new LinkedHashMap<>();
        window.put("from", m.windowFrom());
        window.put("to", m.windowTo());
        root.put("window", window);
        root.put("turns_seen", m.turnsSeen());
        root.put("findings_by_rule", m.findingsByRule());
        root.put("findings_by_action", m.findingsByAction());
        root.put("blocks", m.blocks());
        root.put("postures", m.postures());
        root.put("config_fingerprints", m.configFingerprints());
        root.put("covered_population", m.coveredPopulation());

        Map<String, Object> chain = new LinkedHashMap<>();
        chain.put("status", m.chain().ok() ? "OK" : "BROKEN");
        chain.put("entries", m.chain().entries());
        chain.put("first_broken_seq", m.chain().firstBrokenSeq() < 0 ? null : m.chain().firstBrokenSeq());
        chain.put("head_hash", AttestationReportRenderer.safeHash(m.chain().headHash()));
        chain.put("detail", AttestationReportRenderer.contentFreeChainDetail(m.chain()));
        chain.put("legacy_unchained_rows", m.chain().legacyRows());
        root.put("chain", chain);

        var c = m.coverage();
        Map<String, Object> coverage = new LinkedHashMap<>();
        coverage.put("status", c.status());
        coverage.put("ledger_status", c.ledgerStatus());
        coverage.put("flow_provider_events", c.flowProviderEvents());
        coverage.put("flow_bytes", c.flowBytes());
        coverage.put("envoy_provider_requests", c.providerRequests());
        coverage.put("records", c.records());
        coverage.put("gate_provider_egress_records", c.records());
        coverage.put("records_matched", c.recordsMatched());
        coverage.put("coverage_gaps", c.coverageGaps());
        coverage.put("records_without_envoy_evidence", c.recordsWithoutEnvoyEvidence());
        coverage.put("flow_without_envoy_evidence", c.flowWithoutEnvoyEvidence());
        coverage.put("envoy_without_flow_evidence", c.envoyWithoutFlowEvidence());
        coverage.put("fail_open_uninspected_minutes", c.failOpenUninspectedMinutes());
        coverage.put("coverage_percent", c.coveragePercent());
        coverage.put("provider_requests_by_path", c.providerRequestsByPath());
        coverage.put("fail_open_requests_by_minute", c.failOpenRequestsByMinute());
        coverage.put("provider_flows_by_destination", c.providerFlowsByDestination());
        coverage.put("unclassified_flow_events", c.unclassifiedFlowEvents());
        Long unexplained = unexplainedProviderRequests(c);
        coverage.put("unexplained_provider_requests", unexplained);
        coverage.put("zero_unexplained_provider_requests",
                "VERIFIED".equals(c.ledgerStatus())
                        && unexplained != null && unexplained == 0);
        coverage.put("note", c.note());
        root.put("coverage", coverage);

        var continuation = m.safeContinuation();
        Map<String, Object> safeContinuation = new LinkedHashMap<>();
        safeContinuation.put("recovery_scopes", continuation.recoveryScopes());
        safeContinuation.put("eligible", continuation.eligible());
        safeContinuation.put("attempted", continuation.attempted());
        safeContinuation.put("delivered", continuation.delivered());
        safeContinuation.put("rejected", continuation.rejected());
        safeContinuation.put("failed_closed", continuation.failedClosed());
        safeContinuation.put("completed", continuation.completed());
        safeContinuation.put("failed", continuation.failed());
        safeContinuation.put("fallback", continuation.fallback());
        safeContinuation.put("source_block_turns", continuation.sourceBlockTurns());
        safeContinuation.put("source_mask_turns", continuation.sourceMaskTurns());
        safeContinuation.put("derived_flag_turns", continuation.derivedFlagTurns());
        safeContinuation.put("linked_pairs", continuation.linkedPairs());
        safeContinuation.put("original_bytes_withheld", continuation.originalBytesWithheld());
        safeContinuation.put("transformed_bytes_inspected", continuation.transformedBytesInspected());
        safeContinuation.put("transformed_bytes_egressed", continuation.transformedBytesEgressed());
        safeContinuation.put("turns_by_agent", continuation.turnsByAgent());
        safeContinuation.put("turns_by_provider", continuation.turnsByProvider());
        safeContinuation.put("outcomes_by_agent_version", continuation.outcomesByAgentVersion());
        safeContinuation.put("outcomes_by_status", continuation.outcomesByStatus());
        safeContinuation.put("recipe_versions", continuation.recipeVersions());
        safeContinuation.put("workflow_profile_versions", continuation.workflowProfileVersions());
        safeContinuation.put("coverage_gaps", continuation.coverageGaps());
        Map<String, Object> outcomeIntegrity = new LinkedHashMap<>();
        outcomeIntegrity.put("status", continuation.outcomeIntegrity().status());
        outcomeIntegrity.put("entries", continuation.outcomeIntegrity().entries());
        outcomeIntegrity.put("first_broken_seq", continuation.outcomeIntegrity().firstBrokenSeq());
        outcomeIntegrity.put("detail", continuation.outcomeIntegrity().detail());
        outcomeIntegrity.put("head_hash",
                AttestationReportRenderer.safeHash(continuation.outcomeIntegrity().headHash()));
        outcomeIntegrity.put("integrity_gaps", continuation.outcomeIntegrity().integrityGaps());
        safeContinuation.put("outcome_integrity", outcomeIntegrity);
        root.put("safe_continuation", safeContinuation);

        var b = m.inspectedBytes();
        Map<String, Object> bytes = new LinkedHashMap<>();
        bytes.put("status", b.status());
        bytes.put("inspected_bytes", b.inspectedBytes());
        bytes.put("egressed_bytes", b.egressedBytes());
        bytes.put("flow_bytes", b.flowBytes());
        bytes.put("uninspected_bytes", b.uninspectedBytes());
        bytes.put("inspected_percent", b.inspectedPercent());
        bytes.put("records_missing_byte_counts", b.recordsMissingByteCounts());
        bytes.put("note", b.note());
        root.put("inspected_bytes", bytes);

        Map<String, Object> edm = new LinkedHashMap<>();
        m.edmEvents().forEach((registry, event) -> {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("registry", event.registry());
            row.put("events", event.events());
            row.put("distinct_matches", event.distinctMatches());
            row.put("block_events", event.blockEvents());
            row.put("flag_events", event.flagEvents());
            row.put("note", event.note());
            edm.put(registry, row);
        });
        root.put("edm_events", edm);

        var s = m.registryStaleness();
        Map<String, Object> registryStaleness = new LinkedHashMap<>();
        registryStaleness.put("status", s.status());
        registryStaleness.put("note", s.note());
        registryStaleness.put("registries", s.registries());
        root.put("registry_staleness", registryStaleness);

        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root) + "\n";
        } catch (Exception e) {
            throw new IllegalStateException("failed to serialize report JSON", e);
        }
    }

    // ---- HTML (hand-rolled, no template library; rendering lives in
    // AttestationReportRenderer) ----

    /** Thin delegate kept so existing callers/tests need no changes. */
    static String toHtml(ReportModel m) {
        return AttestationReportRenderer.toHtml(m);
    }

    private static ReportModel.RegistryStaleness registryStaleness(Path dir) throws IOException {
        if (!Files.isDirectory(dir)) {
            return ReportModel.RegistryStaleness.unverified(
                    "EDM registry directory does not exist; staleness cannot be verified.");
        }
        List<ReportModel.RegistryStalenessEntry> entries;
        try (var files = Files.list(dir)) {
            entries = files.filter(p -> p.toString().endsWith(".json"))
                    .sorted()
                    .map(AttestationReporter::readRegistryStalenessEntry)
                    .flatMap(java.util.Optional::stream)
                    .toList();
        }
        return new ReportModel.RegistryStaleness("UNVERIFIED", entries,
                "The current EDM registry format has no push/index timestamp; source file "
                        + "timestamps are shown for operator context, and age_seconds is withheld.");
    }

    private static java.util.Optional<ReportModel.RegistryStalenessEntry> readRegistryStalenessEntry(
            Path file) {
        try {
            JsonNode root = MAPPER.readTree(Files.readString(file));
            String registry = root.path("registry").asText("");
            if (registry.isBlank()) {
                return java.util.Optional.empty();
            }
            var modified = Files.getLastModifiedTime(file);
            long fingerprints = root.path("fingerprints").isArray()
                    ? root.path("fingerprints").size() : 0;
            return java.util.Optional.of(new ReportModel.RegistryStalenessEntry(
                    registry, fingerprints, modified.toInstant().toString(), null,
                    file.getFileName().toString()));
        } catch (Exception e) {
            return java.util.Optional.empty();
        }
    }

    /** Package-private: shared by {@link #toJson} here and {@code toHtml} rendering. */
    static Long unexplainedProviderRequests(ReportModel.Coverage coverage) {
        if (coverage.coverageGaps() == null
                || coverage.flowWithoutEnvoyEvidence() == null
                || coverage.unclassifiedFlowEvents() == null) {
            return null;
        }
        try {
            return Math.addExact(Math.addExact(coverage.coverageGaps(),
                    coverage.flowWithoutEnvoyEvidence()), coverage.unclassifiedFlowEvents());
        } catch (ArithmeticException overflow) {
            return Long.MAX_VALUE;
        }
    }
}
