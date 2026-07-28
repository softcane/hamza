package ai.hamza.attest;

import org.junit.jupiter.api.Test;

import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Reconciliation matching logic: count provider-bound Envoy
 * requests in a window and compare to Gate Records; the shortfall is a coverage gap.
 */
class AccessLogReconcilerTest {

    private static String line(String ts, String cluster, String path) {
        return line(ts, cluster, path, "rid", 10);
    }

    private static String line(String ts, String cluster, String path, String requestId, long bytes) {
        return line(ts, cluster, path, requestId, bytes, "via_upstream");
    }

    private static String line(String ts, String cluster, String path, String requestId, long bytes,
                               String details) {
        return "{\"log\":\"access\",\"start_time\":\"" + ts + "\",\"method\":\"POST\",\"path\":\""
                + path + "\",\"response_code\":200,\"upstream_cluster\":\"" + cluster
                + "\",\"request_id\":\"" + requestId + "\",\"bytes_received\":\"" + bytes
                + "\",\"bytes_sent\":\"20\",\"response_code_details\":\"" + details + "\"}";
    }

    private static RecordRow row(String turnId, String requestId, String action,
                                 Long inspectedBytes, Long egressedBytes) {
        return new RecordRow(1, turnId, requestId, "sess", "codex", "openai",
                "gpt-5-codex", "gpt-5-codex", "completed", 0, 0, 0, 0, 0, 0, 0,
                action, 5, "2026-07-06T10:00:01Z", "FLAG", "fp",
                RecordHasher.CURRENT_RECORD_VERSION, RecordHasher.GENESIS,
                RecordHasher.GENESIS, egressedBytes, inspectedBytes, egressedBytes,
                "BLOCK".equals(action)
                        ? List.of(new Finding("edm-customers", Action.BLOCK))
                        : List.of(),
                Map.of());
    }

    private static FlowFeedReconciler.FlowEntry flow(String ts, String domain) {
        return new FlowFeedReconciler.FlowEntry(ts, domain, "", "FORWARDED", 10);
    }

    @Test
    void parsesOnlyAccessLinesAndIgnoresOperationalLogs() {
        String raw = String.join("\n",
                "[2026-07-06 10:00:00.000][1][info] envoy starting up",
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/v1/responses"),
                "not json at all",
                "{\"log\":\"other\",\"foo\":1}");
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(raw);
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).upstreamCluster()).isEqualTo("provider_upstream");
        assertThat(entries.get(0).path()).isEqualTo("/v1/responses");
    }

    @Test
    void queryStringsAreStrippedFromLoggedPaths() {
        // Query params are the one place a URL could carry content into the report;
        // the parser drops them so aggregation is by bare path (content-free).
        var entries = AccessLogReconciler.parse(
                line("2026-07-06T10:00:01.000Z", "provider_upstream",
                        "/v1/responses?stream=true&user=jane"));
        assertThat(entries.get(0).path()).isEqualTo("/v1/responses");
    }

    @Test
    void localExtProcBlocksAreNotCountedAsProviderEgress() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(String.join("\n",
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/v1/responses",
                        "blocked", 10, "ext_proc_immediate_response"),
                line("2026-07-06T10:00:02.000Z", "provider_upstream", "/v1/responses",
                        "ok", 10, "via_upstream")));

        var r = AccessLogReconciler.reconcile(entries, 1,
                "2026-07-06T10:00:00Z", "2026-07-06T11:00:00Z");

        assertThat(r.providerRequests()).isEqualTo(1);
        assertThat(r.coverageGaps()).isZero();
    }

    @Test
    void bodyBearingSseRequestCountsWhenDownstreamDisconnectsAfterProviderEgress() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/backend-api/codex/responses",
                        "streamed", 4096, "downstream_remote_disconnect"));

        var r = AccessLogReconciler.reconcile(entries, 1,
                "2026-07-06T10:00:00Z", "2026-07-06T11:00:00Z");

        assertThat(r.providerRequests()).isEqualTo(1);
        assertThat(r.coverageGaps()).isZero();
    }

    @Test
    void zeroBodyLocalRejectionWithEmptyDetailIsNotProviderEgress() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/backend-api/codex/models",
                        "local-rejection", 0, ""));

        var r = AccessLogReconciler.reconcile(entries, 0,
                "2026-07-06T10:00:00Z", "2026-07-06T11:00:00Z");

        assertThat(r.providerRequests()).isZero();
        assertThat(r.coverageGaps()).isZero();
    }

    @Test
    void countsOnlyProviderBoundRequestsInsideTheWindow() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(String.join("\n",
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/v1/responses"),
                line("2026-07-06T10:00:02.000Z", "provider_upstream", "/v1/messages"),
                line("2026-07-06T10:00:03.000Z", "", "/ready"),                 // not provider-bound
                line("2026-07-06T09:59:00.000Z", "provider_upstream", "/v1/responses"), // before window
                line("2026-07-06T11:00:00.000Z", "provider_upstream", "/v1/responses"))); // at/after window

        var r = AccessLogReconciler.reconcile(entries, 2,
                "2026-07-06T10:00:00Z", "2026-07-06T11:00:00Z");
        assertThat(r.providerRequests()).isEqualTo(2);
        assertThat(r.records()).isEqualTo(2);
        assertThat(r.recordsMatched()).isEqualTo(2);
        assertThat(r.coverageGaps()).isZero();
        assertThat(r.providerRequestsByPath())
                .containsEntry("/v1/responses", 1L)
                .containsEntry("/v1/messages", 1L);
    }

    @Test
    void aProviderRequestWithoutARecordIsACoverageGap() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(String.join("\n",
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/v1/responses"),
                line("2026-07-06T10:00:02.000Z", "provider_upstream", "/v1/responses"),
                line("2026-07-06T10:00:03.000Z", "provider_upstream", "/v1/responses")));
        // Envoy forwarded 3, but only 1 Record exists (e.g. a fail-open window).
        var r = AccessLogReconciler.reconcile(entries, 1,
                "2026-07-06T10:00:00Z", "2026-07-06T11:00:00Z");
        assertThat(r.providerRequests()).isEqualTo(3);
        assertThat(r.recordsMatched()).isEqualTo(1);
        assertThat(r.coverageGaps()).isEqualTo(2);
        assertThat(r.recordsWithoutEnvoyEvidence()).isZero();
    }

    @Test
    void moreRecordsThanEnvoyEvidenceIsSurfacedAsADiscrepancy() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/v1/responses"));
        var r = AccessLogReconciler.reconcile(entries, 3,
                "2026-07-06T10:00:00Z", "2026-07-06T11:00:00Z");
        assertThat(r.coverageGaps()).isZero();
        assertThat(r.recordsWithoutEnvoyEvidence()).isEqualTo(2);
    }

    @Test
    void requestIdCorrelationDoesNotNetBlockedTurnsAgainstFailOpenGaps() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(String.join("\n",
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/v1/responses", "rid-ok", 10),
                line("2026-07-06T10:00:02.000Z", "provider_upstream", "/v1/responses", "rid-gap", 7)));
        List<RecordRow> rows = List.of(
                row("t-ok", "rid-ok", "FLAG", 10L, 10L),
                row("t-block", "rid-block", "BLOCK", 20L, 0L));
        var flows = List.of(
                flow("2026-07-06T10:00:01Z", "api.openai.com"),
                flow("2026-07-06T10:00:02Z", "api.openai.com"));

        var r = AccessLogReconciler.reconcile(entries, rows, flows, Set.of("api.openai.com"),
                "2026-07-06T10:00:00Z", "2026-07-06T11:00:00Z");

        assertThat(r.providerRequests()).isEqualTo(2);
        assertThat(r.records()).isEqualTo(1); // blocked zero-egress Record is not expected in Envoy
        assertThat(r.recordsMatched()).isEqualTo(1);
        assertThat(r.coverageGaps()).isEqualTo(1);
        assertThat(r.recordsWithoutEnvoyEvidence()).isZero();
        assertThat(r.failOpenUninspectedMinutes()).isEqualTo(1);
        assertThat(r.providerEgressBytes()).isEqualTo(17);
        assertThat(r.inspectedEgressBytes()).isEqualTo(10);
        assertThat(r.uninspectedEgressBytes()).isEqualTo(7);
    }

    @Test
    void failOpenMinutesAreDistinctUtcMinuteBuckets() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(String.join("\n",
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/v1/responses", "gap-1", 1),
                line("2026-07-06T10:00:40.000Z", "provider_upstream", "/v1/responses", "gap-2", 1),
                line("2026-07-06T10:01:01.000Z", "provider_upstream", "/v1/responses", "gap-3", 1)));

        var r = AccessLogReconciler.reconcile(entries, List.of(), List.of(
                        flow("2026-07-06T10:00:01Z", "api.openai.com"),
                        flow("2026-07-06T10:00:40Z", "api.openai.com"),
                        flow("2026-07-06T10:01:01Z", "api.openai.com")),
                Set.of("api.openai.com"), "2026-07-06T10:00:00Z", "2026-07-06T11:00:00Z");

        assertThat(r.coverageGaps()).isEqualTo(3);
        assertThat(r.failOpenUninspectedMinutes()).isEqualTo(2);
        assertThat(r.failOpenRequestsByMinute())
                .containsEntry("2026-07-06T10:00:00Z", 2L)
                .containsEntry("2026-07-06T10:01:00Z", 1L);
    }

    @Test
    void flowFeedDiscrepanciesAreReportedSeparately() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(String.join("\n",
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/v1/responses", "rid-1", 1),
                line("2026-07-06T10:00:02.000Z", "provider_upstream", "/v1/responses", "rid-2", 1)));
        var flows = List.of(flow("2026-07-06T10:00:01Z", "api.openai.com"));

        var r = AccessLogReconciler.reconcile(entries, List.of(), flows, Set.of("api.openai.com"),
                "2026-07-06T10:00:00Z", "2026-07-06T11:00:00Z");

        assertThat(r.flowProviderEvents()).isEqualTo(1);
        assertThat(r.envoyWithoutFlowEvidence()).isEqualTo(1);
        assertThat(r.flowWithoutEnvoyEvidence()).isZero();
    }

    @Test
    void cleanThreeLedgerWindowHasZeroUnexplainedProviderRequests() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/v1/responses",
                        "rid-ok", 10));
        List<RecordRow> rows = List.of(row("turn-ok", "rid-ok", "FLAG", 10L, 10L));
        List<FlowFeedReconciler.FlowEntry> flows = List.of(
                flow("2026-07-06T10:00:01Z", "api.openai.com"));

        var reconciliation = AccessLogReconciler.reconcile(entries, rows, flows,
                Set.of("api.openai.com"), "2026-07-06T10:00:00Z",
                "2026-07-06T11:00:00Z");

        assertThat(reconciliation.hasLedgerMismatch()).isFalse();
        assertThat(reconciliation.unexplainedProviderRequests()).isZero();
        assertThat(ReportModel.Coverage.verified(reconciliation).status())
                .isEqualTo("VERIFIED");
    }

    @Test
    void zeroBodyCompletedRecordReconcilesProviderHeadProbe() {
        List<AccessLogReconciler.AccessEntry> entries = AccessLogReconciler.parse(
                line("2026-07-06T10:00:01.000Z", "provider_upstream", "/",
                        "rid-head", 0));
        List<RecordRow> rows = List.of(row("turn-head", "rid-head", "FLAG", 0L, 0L));
        List<FlowFeedReconciler.FlowEntry> flows = List.of(
                flow("2026-07-06T10:00:01Z", "api.anthropic.com"));

        var reconciliation = AccessLogReconciler.reconcile(entries, rows, flows,
                Set.of("api.anthropic.com"), "2026-07-06T10:00:00Z",
                "2026-07-06T11:00:00Z");

        assertThat(reconciliation.providerRequests()).isOne();
        assertThat(reconciliation.records()).isOne();
        assertThat(reconciliation.recordsMatched()).isOne();
        assertThat(reconciliation.hasLedgerMismatch()).isFalse();
    }
}
