package ai.hamza.attest;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Golden byte-for-byte pin of {@link AttestationReporter#toJson} and
 * {@link AttestationReporter#toHtml}. Both methods are static and pure, but the existing
 * {@code AttestationReporterTest} only asserts shape and substrings — a rendering
 * regression (a dropped row, a re-ordered field, an escaping change) would still pass
 * that suite. R3 moves this rendering code; this test pins its exact byte output first,
 * against a fixed, fully-populated {@link ReportModel} covering the OK-chain-with-legacy-
 * rows, VERIFIED-coverage, VERIFIED-byte-inspection, non-empty EDM/registry/mapTable
 * branches so the fixture is sensitive to real regressions in every rendered section.
 */
class AttestationReporterGoldenTest {

    @Test
    void toJsonAndToHtmlMatchTheCommittedGoldenFixtureByteForByte() throws IOException {
        ReportModel model = fixedModel();

        String json = AttestationReporter.toJson(model);
        String html = AttestationReporter.toHtml(model);

        String goldenJson = fixture("/attest/attestation-report-golden.json");
        String goldenHtml = fixture("/attest/attestation-report-golden.html");

        assertThat(json).isEqualTo(goldenJson);
        assertThat(html).isEqualTo(goldenHtml);
    }

    private static String fixture(String resource) throws IOException {
        try (var in = AttestationReporterGoldenTest.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("missing fixture: " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * A fixed, deterministic {@link ReportModel} built directly (not through
     * {@link ReportModel#build}) so every field — including the ones {@code build} only
     * derives from live rows — is a fake, fully-populated, non-default value. Chosen to
     * walk the OK+legacy-rows chain branch, the VERIFIED coverage branch (so the
     * provider-requests HTML table renders), the VERIFIED byte-inspection branch, and
     * non-empty EDM/registry/mapTable rendering.
     */
    private static ReportModel fixedModel() {
        ChainVerifier.Result chain = new ChainVerifier.Result(true, 5, -1, null,
                "f".repeat(64), 1);

        Map<String, Long> byPath = new LinkedHashMap<>();
        byPath.put("/v1/responses", 8L);
        Map<String, Long> byMinute = new LinkedHashMap<>();
        byMinute.put("2026-07-27T10:00", 1L);
        Map<String, Long> byDestination = new LinkedHashMap<>();
        byDestination.put("api.openai.com", 8L);
        ReportModel.Coverage coverage = new ReportModel.Coverage("VERIFIED", "VERIFIED",
                10L, 1000L, 8L, 8L, 7L, 1L, 0L, 0L, 1L, 2L, 87.5,
                byPath, byMinute, byDestination, 0L,
                "fixed fake coverage note for the golden fixture.");

        ReportModel.ByteInspection inspectedBytes = new ReportModel.ByteInspection(
                "VERIFIED", 900L, 1000L, 1000L, 100L, 90.0, 0L,
                "fixed fake byte-inspection note for the golden fixture.");

        Map<String, ReportModel.EdmEventSummary> edmEvents = new LinkedHashMap<>();
        edmEvents.put("customers", new ReportModel.EdmEventSummary(
                "customers", 3, 5L, 1, 2, "fixed fake edm note."));

        ReportModel.RegistryStaleness registryStaleness = new ReportModel.RegistryStaleness(
                "UNVERIFIED",
                List.of(new ReportModel.RegistryStalenessEntry(
                        "customers", 5, "2026-07-01T00:00:00Z", null, "customers.json")),
                "fixed fake registry-staleness note.");

        Map<String, Long> byRule = new LinkedHashMap<>();
        byRule.put("aws-access-key-id", 2L);
        byRule.put("edm-customers", 1L);
        Map<String, Long> byAction = new LinkedHashMap<>();
        byAction.put("MASK", 2L);
        byAction.put("BLOCK", 1L);
        Map<String, Long> postures = new LinkedHashMap<>();
        postures.put("MASK", 3L);
        postures.put("FLAG", 2L);
        Map<String, Long> fingerprints = new LinkedHashMap<>();
        fingerprints.put("cfg-fp-abc", 5L);

        ContinuationAttestation.OutcomeIntegrity outcomeIntegrity =
                new ContinuationAttestation.OutcomeIntegrity("OK", 2, null, null,
                        "e".repeat(64), 0);
        Map<String, Long> turnsByAgent = new LinkedHashMap<>();
        turnsByAgent.put("codex", 3L);
        turnsByAgent.put("claude-code", 1L);
        Map<String, Long> turnsByProvider = new LinkedHashMap<>();
        turnsByProvider.put("openai", 3L);
        turnsByProvider.put("anthropic", 1L);
        Map<String, Long> outcomesByAgentVersion = new LinkedHashMap<>();
        outcomesByAgentVersion.put("codex-0.144", 2L);
        Map<String, Long> outcomesByStatus = new LinkedHashMap<>();
        outcomesByStatus.put("COMPLETED", 2L);
        Map<String, Long> recipeVersions = new LinkedHashMap<>();
        recipeVersions.put("1", 3L);
        Map<String, Long> workflowProfileVersions = new LinkedHashMap<>();
        workflowProfileVersions.put("1", 3L);
        Map<String, Long> coverageGaps = new LinkedHashMap<>();
        coverageGaps.put("fixed-fake-gap-kind", 1L);
        ContinuationAttestation.Summary safeContinuation = new ContinuationAttestation.Summary(
                4, 4, 3, 2, 1, 1, 2, 0, 0, 1, 2, 2, 2, 500, 400, 380,
                turnsByAgent, turnsByProvider, outcomesByAgentVersion, outcomesByStatus,
                recipeVersions, workflowProfileVersions, coverageGaps, outcomeIntegrity);

        return new ReportModel(ReportModel.SCHEMA_VERSION, "2026-07-27T12:00:00Z",
                "2026-07-27T00:00:00Z", "2026-07-28T00:00:00Z", 5,
                byRule, byAction, 1, postures, fingerprints, chain, coverage, inspectedBytes,
                edmEvents, registryStaleness, "fixed test covered population", safeContinuation);
    }
}
