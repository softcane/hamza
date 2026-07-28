package ai.hamza.attest;

import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ContinuationAttestationTest {

    @Test
    void reportsLinkedSourceDerivedAndVerifiedOutcomeAccountingWithoutContent() {
        RecordRow source = source("source-1", "recovery-1", "eligible-edm", List.of(
                new Finding("exact-data-match", Action.BLOCK)));
        RecordRow derived = derived("derived-1", "source-1", "recovery-1", Action.FLAG,
                List.of());
        RecoveryOutcomeRow outcome = outcome("recovery-1", "completed");
        RecoveryOutcomeChainVerifier.Result outcomeChain = new RecoveryOutcomeChainVerifier.Result(
                true, 1, -1, "ok", "a".repeat(64), 0);

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(source, derived), List.of(source, derived), List.of(outcome), outcomeChain);

        assertThat(summary.recoveryScopes()).isEqualTo(1);
        assertThat(summary.eligible()).isEqualTo(1);
        assertThat(summary.attempted()).isEqualTo(1);
        assertThat(summary.delivered()).isEqualTo(1);
        assertThat(summary.completed()).isEqualTo(1);
        assertThat(summary.sourceBlockTurns()).isEqualTo(1);
        assertThat(summary.derivedFlagTurns()).isEqualTo(1);
        assertThat(summary.linkedPairs()).isEqualTo(1);
        assertThat(summary.originalBytesWithheld()).isEqualTo(128);
        assertThat(summary.transformedBytesInspected()).isEqualTo(96);
        assertThat(summary.transformedBytesEgressed()).isEqualTo(96);
        assertThat(summary.turnsByAgent()).containsExactly(Map.entry("codex", 2L));
        assertThat(summary.turnsByProvider()).containsExactly(Map.entry("openai", 2L));
        assertThat(summary.outcomesByAgentVersion())
                .containsExactly(Map.entry("codex:0.144.0", 1L));
        assertThat(summary.outcomesByStatus()).containsExactly(Map.entry("completed", 1L));
        assertThat(summary.coverageGaps()).isEmpty();
        assertThat(summary.toString())
                .doesNotContain("recovery-1", "source-1", "derived-1");
    }

    @Test
    void acceptsM5MaskedSourceWithPositiveMaskCountAsWithheldEvidence() {
        RecordRow source = maskedSource("source-1", "recovery-1", 2,
                List.of(new Finding("email-address", Action.MASK)));
        RecordRow derived = derived("derived-1", "source-1", "recovery-1", Action.FLAG,
                List.of());
        RecoveryOutcomeChainVerifier.Result outcomeChain = new RecoveryOutcomeChainVerifier.Result(
                true, 1, -1, "ok", "a".repeat(64), 0);

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(source, derived), List.of(source, derived),
                List.of(outcome("recovery-1", "completed")), outcomeChain);

        assertThat(summary.eligible()).isEqualTo(1);
        assertThat(summary.completed()).isEqualTo(1);
        assertThat(summary.sourceBlockTurns()).isZero();
        assertThat(summary.sourceMaskTurns()).isEqualTo(1);
        assertThat(summary.originalBytesWithheld()).isEqualTo(128);
        assertThat(summary.coverageGaps()).isEmpty();
    }

    @Test
    void maskedSourceWithoutAPositiveMaskCountIsAnExplicitGap() {
        RecordRow source = maskedSource("source-1", "recovery-1", 0,
                List.of(new Finding("email-address", Action.MASK)));

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(source), List.of(source), List.of(), null);

        assertThat(summary.sourceMaskTurns()).isZero();
        assertThat(summary.coverageGaps())
                .containsEntry("source-mask-count-invalid", 1L);
    }

    @Test
    void unsafeSourceEvidenceProducesExplicitCoverageGapClasses() {
        RecordRow source = row(1, "source-1", "request-source", "BLOCK",
                128L, 128L, 8L,
                new RecordHasher.ContinuationHashFields(
                        "SOURCE", "recovery-1", null, "synthetic-email", 1,
                        "repo-safe-edit", 1, "ATTEMPTED", "failed-source-scan-incomplete",
                        "one-way", "UNVERIFIED", 120L),
                List.of(new Finding("scan-incomplete", Action.BLOCK)));

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(source), List.of(source), List.of(), null);

        assertThat(summary.failedClosed()).isEqualTo(1);
        assertThat(summary.coverageGaps())
                .containsEntry("scan-incomplete", 1L)
                .containsEntry("source-nonzero-egress", 1L)
                .containsEntry("source-byte-accounting-invalid", 1L)
                .doesNotContainKeys("missing-derived-record", "missing-recovery-outcome");
    }

    @Test
    void derivedTurnWithoutAFlagOnlyLinkedSourceIsAnExplicitGap() {
        RecordRow derived = derived("derived-1", "missing-source", "recovery-1",
                Action.MASK, List.of(new Finding("aws-access-key-id", Action.MASK)));

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(derived), List.of(derived), List.of(), null);

        assertThat(summary.delivered()).isEqualTo(1);
        assertThat(summary.derivedFlagTurns()).isZero();
        assertThat(summary.coverageGaps())
                .containsEntry("derived-not-flag-only", 1L)
                .containsEntry("missing-source-record", 1L)
                .doesNotContainKey("missing-recovery-outcome");
    }

    @Test
    void failedLocalAcceptanceEvidenceIsNeverCountedAsCompleted() {
        RecordRow source = source("source-1", "recovery-1", "eligible-edm",
                List.of(new Finding("exact-data-match", Action.BLOCK)));
        RecordRow derived = derived("derived-1", "source-1", "recovery-1", Action.FLAG,
                List.of());
        RecoveryOutcomeChainVerifier.Result verified = new RecoveryOutcomeChainVerifier.Result(
                true, 1, -1, "ok", "a".repeat(64), 0);

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(source, derived), List.of(source, derived),
                List.of(outcome("recovery-1", "failed")), verified);

        assertThat(summary.completed()).isZero();
        assertThat(summary.failed()).isEqualTo(1);
        assertThat(summary.fallback()).isZero();
        assertThat(summary.coverageGaps()).isEmpty();
    }

    @Test
    void outcomeConflictOrSignatureFailureIsAnEvidenceIntegrityGap() {
        RecordRow source = source("source-1", "recovery-1", "eligible-edm",
                List.of(new Finding("exact-data-match", Action.BLOCK)));
        RecordRow derived = derived("derived-1", "source-1", "recovery-1", Action.FLAG,
                List.of());
        RecoveryOutcomeChainVerifier.Result broken = new RecoveryOutcomeChainVerifier.Result(
                false, 1, -1, "evidence integrity gap", "a".repeat(64), 1);

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(source, derived), List.of(source, derived),
                List.of(outcome("recovery-1", "completed")), broken);

        assertThat(summary.outcomeIntegrity().status()).isEqualTo("BROKEN");
        assertThat(summary.completed()).isZero();
        assertThat(summary.outcomesByStatus()).containsEntry("unverified", 1L);
        assertThat(summary.coverageGaps())
                .containsEntry("recovery-outcome-integrity-invalid", 1L);
    }

    @Test
    void durableOutcomeConflictRemainsVisibleWhenSignatureKeyIsUnavailable() {
        RecordRow source = source("source-1", "recovery-1", "eligible-edm",
                List.of(new Finding("exact-data-match", Action.BLOCK)));
        RecordRow derived = derived("derived-1", "source-1", "recovery-1", Action.FLAG,
                List.of());

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(source, derived), List.of(source, derived),
                List.of(outcome("recovery-1", "completed")), null, 1);

        assertThat(summary.completed()).isZero();
        assertThat(summary.outcomeIntegrity().status()).isEqualTo("UNVERIFIED");
        assertThat(summary.outcomeIntegrity().integrityGaps()).isEqualTo(1);
        assertThat(summary.coverageGaps())
                .containsEntry("recovery-outcome-verification-unavailable", 1L)
                .containsEntry("recovery-outcome-integrity-invalid", 1L);
    }

    @Test
    void signedOutcomeWithoutDerivedRecordRemainsUnverified() {
        RecordRow source = source("source-1", "recovery-1", "eligible-edm",
                List.of(new Finding("exact-data-match", Action.BLOCK)));
        RecoveryOutcomeChainVerifier.Result verified = new RecoveryOutcomeChainVerifier.Result(
                true, 1, -1, "ok", "a".repeat(64), 0);

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(source), List.of(source),
                List.of(outcome("recovery-1", "completed")), verified);

        assertThat(summary.completed()).isZero();
        assertThat(summary.outcomesByStatus()).containsEntry("unverified", 1L);
        assertThat(summary.coverageGaps()).containsEntry("missing-derived-record", 1L);
    }

    @Test
    void expectedIneligibleSourceNeedsNeitherDerivedTurnNorRecoveryOutcome() {
        RecordRow source = source("source-1", "recovery-1",
                "ineligible-unsupported-workflow-shape",
                List.of(new Finding("continuation-ineligible", Action.BLOCK)));

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(source), List.of(source), List.of(), null);

        assertThat(summary.attempted()).isEqualTo(1);
        assertThat(summary.rejected()).isEqualTo(1);
        assertThat(summary.delivered()).isZero();
        assertThat(summary.coverageGaps()).doesNotContainKeys(
                "missing-derived-record", "missing-recovery-outcome",
                "recovery-outcome-verification-unavailable");
    }

    @Test
    void observeOnlyScanExhaustionDemotesOtherwiseCleanCoverage() throws Exception {
        RecordRow simulation = row(1, "turn-1", "request-1", "FLAG",
                64L, 64L, 64L, RecordHasher.ContinuationHashFields.none(),
                List.of(new Finding("scan-incomplete", Action.FLAG)));
        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(simulation), List.of(simulation), List.of(), null);
        var access = List.of(new AccessLogReconciler.AccessEntry(
                "2026-07-11T10:00:01Z", "POST", "/v1/responses", 200,
                AccessLogReconciler.PROVIDER_CLUSTER, "request-1", 64, 20,
                "via_upstream"));
        var flows = List.of(new FlowFeedReconciler.FlowEntry(
                "2026-07-11T10:00:01Z", "api.openai.com", "", "FORWARDED", 64));
        AccessLogReconciler.Reconciliation reconciliation = AccessLogReconciler.reconcile(
                access, List.of(simulation), flows, Set.of("api.openai.com"),
                "2026-07-11T00:00:00Z", "2026-07-12T00:00:00Z");
        ReportModel.Coverage coverage = ReportModel.Coverage.verified(reconciliation);
        ChainVerifier.Result chain = new ChainVerifier.Result(
                true, 1, -1, "ok", "a".repeat(64), 0);

        ReportModel report = ReportModel.build("2026-07-12T00:00:00Z",
                "2026-07-11T00:00:00Z", "2026-07-12T00:00:00Z",
                List.of(simulation), chain, coverage,
                ReportModel.ByteInspection.fromCoverage(coverage, reconciliation),
                ReportModel.RegistryStaleness.unverified("not supplied"),
                "managed test population", summary);

        var json = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(AttestationReporter.toJson(report));
        assertThat(json.get("coverage").get("status").asText()).isEqualTo("UNVERIFIED");
        assertThat(json.get("coverage").get("ledger_status").asText()).isEqualTo("VERIFIED");
        assertThat(json.get("coverage").get("zero_unexplained_provider_requests").asBoolean())
                .isTrue();
        assertThat(json.get("coverage").get("coverage_percent").isNull()).isTrue();
        assertThat(json.get("safe_continuation").get("coverage_gaps")
                .get("scan-incomplete").asLong()).isEqualTo(1);
    }

    @Test
    void observeOnlyEligibilityIsCountedWithoutInventingAContinuationTurn() {
        RecordRow simulation = row(1, "turn-1", "request-1", "BLOCK",
                64L, 64L, 0L, RecordHasher.ContinuationHashFields.none(),
                List.of(new Finding("edm-customers", Action.BLOCK),
                        new Finding("continuation-simulation-eligible", Action.FLAG)));

        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                List.of(simulation), List.of(simulation), List.of(), null);

        assertThat(summary.attempted()).isEqualTo(1);
        assertThat(summary.eligible()).isEqualTo(1);
        assertThat(summary.sourceBlockTurns()).isZero();
        assertThat(summary.derivedFlagTurns()).isZero();
        assertThat(summary.coverageGaps()).isEmpty();
    }

    @Test
    void linkedEvidenceAndCleanThreeLedgersRenderVerifiedAndContentFree() throws Exception {
        RecordRow source = source("source-1", "recovery-1", "eligible-edm",
                List.of(new Finding("exact-data-match", Action.BLOCK)));
        RecordRow derived = derived("derived-1", "source-1", "recovery-1", Action.FLAG,
                List.of());
        RecoveryOutcomeRow outcome = outcome("recovery-1", "completed");
        RecoveryOutcomeChainVerifier.Result outcomeChain = new RecoveryOutcomeChainVerifier.Result(
                true, 1, -1, "ok", "a".repeat(64), 0);
        List<RecordRow> rows = List.of(source, derived);
        ContinuationAttestation.Summary summary = ContinuationAttestation.evaluate(
                rows, rows, List.of(outcome), outcomeChain);
        var entries = List.of(new AccessLogReconciler.AccessEntry(
                "2026-07-11T10:00:01Z", "POST", "/v1/responses", 200,
                AccessLogReconciler.PROVIDER_CLUSTER, "request-derived", 96, 20,
                "via_upstream"));
        var flows = List.of(new FlowFeedReconciler.FlowEntry(
                "2026-07-11T10:00:01Z", "api.openai.com", "", "FORWARDED", 96));
        AccessLogReconciler.Reconciliation reconciliation = AccessLogReconciler.reconcile(
                entries, rows, flows, Set.of("api.openai.com"),
                "2026-07-11T00:00:00Z", "2026-07-12T00:00:00Z");
        ReportModel.Coverage coverage = ReportModel.Coverage.verified(reconciliation);
        ChainVerifier.Result chain = new ChainVerifier.Result(
                true, 2, -1, "ok", "d".repeat(64), 0);
        ReportModel report = ReportModel.build("2026-07-12T00:00:00Z",
                "2026-07-11T00:00:00Z", "2026-07-12T00:00:00Z", rows,
                chain, coverage, ReportModel.ByteInspection.fromCoverage(coverage, reconciliation),
                ReportModel.RegistryStaleness.unverified("not supplied"),
                "managed test population", summary);

        String jsonText = AttestationReporter.toJson(report);
        var json = new com.fasterxml.jackson.databind.ObjectMapper().readTree(jsonText);
        assertThat(json.get("coverage").get("status").asText()).isEqualTo("VERIFIED");
        assertThat(json.get("coverage").get("zero_unexplained_provider_requests").asBoolean())
                .isTrue();
        assertThat(json.get("safe_continuation").get("source_block_turns").asLong())
                .isEqualTo(1);
        assertThat(json.get("safe_continuation").get("source_mask_turns").asLong())
                .isZero();
        assertThat(json.get("safe_continuation").get("derived_flag_turns").asLong())
                .isEqualTo(1);
        assertThat(json.get("safe_continuation").get("completed").asLong()).isEqualTo(1);
        assertThat(json.get("safe_continuation").get("coverage_gaps").isEmpty()).isTrue();
        assertThat(jsonText).doesNotContain(
                "recovery-1", "source-1", "derived-1", "request-source", "request-derived",
                "mvn-test", "c".repeat(64),
                "alice@example-corp.test",
                "hamza-0123456789abcdef0123456789abcdef@example.invalid");
    }

    private static RecordRow source(String turnId, String recoveryId, String reason,
                                    List<Finding> findings) {
        return row(1, turnId, "request-source", "BLOCK", 128L, 128L, 0L,
                new RecordHasher.ContinuationHashFields(
                        "SOURCE", recoveryId, null, "synthetic-email", 1,
                        "repo-safe-edit", 1, "ATTEMPTED", reason,
                        "one-way", "UNVERIFIED", 128L), findings);
    }

    private static RecordRow derived(String turnId, String parentTurnId, String recoveryId,
                                     Action action, List<Finding> findings) {
        return row(2, turnId, "request-derived", action.name(), 96L, 96L, 96L,
                new RecordHasher.ContinuationHashFields(
                        "DERIVED", recoveryId, parentTurnId, null, null,
                        null, null, "DELIVERED", null, null,
                        "UNVERIFIED", null), findings);
    }

    private static RecordRow maskedSource(String turnId, String recoveryId,
                                          int maskedValueCount, List<Finding> findings) {
        return row(1, turnId, "request-source", "MASK", 128L, 128L, 0L,
                new RecordHasher.ContinuationHashFields(
                        "SOURCE", recoveryId, null, "synthetic-email", 1,
                        "repo-safe-edit", 1, "ATTEMPTED", "masked-secret-edm",
                        "one-way", "UNVERIFIED", 128L, maskedValueCount), findings);
    }

    private static RecordRow row(long seq, String turnId, String requestId, String action,
                                 Long received, Long inspected, Long egressed,
                                 RecordHasher.ContinuationHashFields continuation,
                                 List<Finding> findings) {
        return new RecordRow(seq, turnId, requestId, "scope", "codex", "openai",
                "gpt-5-codex", "gpt-5-codex",
                "BLOCK".equals(action) ? "blocked" : "completed",
                0, 0, 0, 0, 0, 0, 0, action, 5,
                "2026-07-11T10:00:00Z", "BLOCK".equals(action) ? "BLOCK" : "FLAG",
                "cfg", RecordHasher.CURRENT_RECORD_VERSION, RecordHasher.GENESIS,
                "b".repeat(64), received, inspected, egressed, continuation, findings, Map.of());
    }

    private static RecoveryOutcomeRow outcome(String recoveryId, String status) {
        return new RecoveryOutcomeRow(1, RecordHasher.CURRENT_RECOVERY_OUTCOME_VERSION,
                RecordHasher.GENESIS, "a".repeat(64), recoveryId, status, "codex", "0.144.0",
                "repo-safe-edit", 1, "mvn-test", "2026-07-11T10:05:00Z",
                "2026-07-11T10:06:00Z", "hamza-recovery-outcome-signature/v1",
                "c".repeat(64));
    }
}
