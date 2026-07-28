package ai.hamza.attest;

import ai.hamza.policy.Finding;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The content-free aggregation behind an attestation report. Counts, rules,
 * Actions, hashes, timestamps, and config fingerprints only — never prompt text, secret
 * values, or body content (content-free invariant). Kept separate from rendering so the
 * shape can be asserted directly in tests.
 */
public record ReportModel(
        String schemaVersion,
        String generatedAt,
        String windowFrom,
        String windowTo,
        long turnsSeen,
        Map<String, Long> findingsByRule,
        Map<String, Long> findingsByAction,
        long blocks,
        Map<String, Long> postures,
        Map<String, Long> configFingerprints,
        ChainVerifier.Result chain,
        Coverage coverage,
        ByteInspection inspectedBytes,
        Map<String, EdmEventSummary> edmEvents,
        RegistryStaleness registryStaleness,
        String coveredPopulation,
        ContinuationAttestation.Summary safeContinuation) {

    public static final String SCHEMA_VERSION = "hamza-attestation/v2";

    public ReportModel {
        safeContinuation = safeContinuation == null
                ? ContinuationAttestation.Summary.empty() : safeContinuation;
    }

    /**
     * Coverage reconciliation. When there is no independent network/
     * access-log feed the status is {@code UNVERIFIED} and the numeric fields are null —
     * the report refuses to imply a coverage number it cannot back.
     */
    public record Coverage(
            String status,
            String ledgerStatus,
            Long flowProviderEvents,
            Long flowBytes,
            Long providerRequests,
            Long records,
            Long recordsMatched,
            Long coverageGaps,
            Long recordsWithoutEnvoyEvidence,
            Long flowWithoutEnvoyEvidence,
            Long envoyWithoutFlowEvidence,
            Long failOpenUninspectedMinutes,
            Double coveragePercent,
            Map<String, Long> providerRequestsByPath,
            Map<String, Long> failOpenRequestsByMinute,
            Map<String, Long> providerFlowsByDestination,
            Long unclassifiedFlowEvents,
            String note) {

        public static Coverage unverified(long records) {
            return new Coverage("UNVERIFIED", "UNVERIFIED", null, null, null, records, null, null, null,
                    null, null, null, null, Map.of(), Map.of(), Map.of(), null,
                    "No independent network flow feed supplied; coverage cannot be "
                            + "verified against the network ledger. Re-run with --flows.");
        }

        public static Coverage unverified(AccessLogReconciler.Reconciliation r) {
            return from(r, "UNVERIFIED",
                    "Envoy access-log evidence was supplied, but no network flow feed was supplied; "
                            + "coverage_percent is withheld until the third ledger is present. "
                            + r.note());
        }

        public static Coverage verified(AccessLogReconciler.Reconciliation r) {
            boolean mismatch = r.hasLedgerMismatch();
            return from(r, mismatch ? "UNVERIFIED" : "VERIFIED",
                    mismatch
                            ? "At least one network, Envoy, or Gate ledger discrepancy is present. "
                                    + r.note()
                            : r.note());
        }

        public Coverage withEvidenceGaps(Map<String, Long> evidenceGaps) {
            long gapCount = evidenceGaps == null ? 0 : evidenceGaps.values().stream()
                    .filter(java.util.Objects::nonNull)
                    .filter(count -> count > 0)
                    .mapToLong(Long::longValue)
                    .sum();
            if (gapCount == 0) {
                return this;
            }
            return new Coverage("UNVERIFIED", ledgerStatus, flowProviderEvents, flowBytes,
                    providerRequests, records, recordsMatched, coverageGaps,
                    recordsWithoutEnvoyEvidence, flowWithoutEnvoyEvidence,
                    envoyWithoutFlowEvidence, failOpenUninspectedMinutes, null,
                    providerRequestsByPath, failOpenRequestsByMinute,
                    providerFlowsByDestination, unclassifiedFlowEvents,
                    note + " " + gapCount
                            + " Safe Continuation evidence coverage gap(s) are listed separately.");
        }

        private static Coverage from(AccessLogReconciler.Reconciliation r, String status,
                                     String extraNote) {
            Double pct = !"VERIFIED".equals(status) || r.providerRequests() == 0
                    ? null
                    : r.recordsMatched() * 100.0 / r.providerRequests();
            String note = r.providerRequests() == 0
                    ? "No provider-bound requests in this window; coverage percent is not applicable."
                    : r.coverageGaps() > 0
                    ? r.coverageGaps() + " provider-bound request(s) Envoy forwarded have no "
                            + "matching Gate Record (uninspected fail-open Egress)."
                    : "Every provider-bound request Envoy forwarded has a matching Gate Record.";
            if (r.recordsWithoutEnvoyEvidence() > 0) {
                note += " " + r.recordsWithoutEnvoyEvidence() + " Record(s) have no Envoy "
                        + "evidence in this window (ledger discrepancy).";
            }
            if (r.flowWithoutEnvoyEvidence() > 0) {
                note += " " + r.flowWithoutEnvoyEvidence()
                        + " provider-domain flow event(s) have no Envoy evidence.";
            }
            if (r.envoyWithoutFlowEvidence() > 0) {
                note += " " + r.envoyWithoutFlowEvidence()
                        + " Envoy provider request(s) have no flow-feed evidence.";
            }
            if (r.unclassifiedFlowEvents() > 0) {
                note += " " + r.unclassifiedFlowEvents()
                        + " allowed flow event(s) were IP-only and could not be classified by Adapter domains.";
            }
            note += " " + extraNote
                    + " Clock-source skew note: Record ts is stamped by hamza-core; Envoy start_time "
                    + "is stamped by Envoy, so boundary requests can land on different sides of a narrow window.";
            return new Coverage(status, status, r.flowProviderEvents(), r.flowBytes(),
                    r.providerRequests(), r.records(), r.recordsMatched(),
                    r.coverageGaps(), r.recordsWithoutEnvoyEvidence(),
                    r.flowWithoutEnvoyEvidence(), r.envoyWithoutFlowEvidence(),
                    r.failOpenUninspectedMinutes(), pct,
                    new TreeMap<>(r.providerRequestsByPath()),
                    new TreeMap<>(r.failOpenRequestsByMinute()),
                    new TreeMap<>(r.providerFlowsByDestination()),
                    r.unclassifiedFlowEvents(), note);
        }
    }

    public record ByteInspection(String status, Long inspectedBytes, Long egressedBytes,
                                 Long flowBytes, Long uninspectedBytes, Double inspectedPercent,
                                 Long recordsMissingByteCounts, String note) {
        public static ByteInspection fromCoverage(Coverage c,
                                                  AccessLogReconciler.Reconciliation r) {
            if (r == null || !"VERIFIED".equals(c.status())) {
                return new ByteInspection("UNVERIFIED", null, null, null, null, null, null,
                        "Inspected-byte percentage is withheld until flow-feed coverage is VERIFIED.");
            }
            long denominator = Math.max(r.providerEgressBytes(), r.flowBytes());
            long uninspected = Math.max(0, denominator - r.inspectedEgressBytes());
            if (r.recordsMissingByteCounts() > 0) {
                return new ByteInspection("UNVERIFIED", r.inspectedEgressBytes(),
                        denominator, r.flowBytes(), uninspected, null,
                        r.recordsMissingByteCounts(),
                        "Some provider-egress Records lack byte counts; no percentage printed.");
            }
            if (denominator == 0) {
                return new ByteInspection("N/A", r.inspectedEgressBytes(), 0L, r.flowBytes(), 0L,
                        null, 0L, "No provider request-body bytes egressed in this window.");
            }
            double pct = r.inspectedEgressBytes() * 100.0 / denominator;
            return new ByteInspection("VERIFIED", r.inspectedEgressBytes(),
                    denominator, r.flowBytes(), uninspected, pct, 0L,
                    "Numerator is inspected provider-egress body bytes from Gate Records; "
                            + "denominator is the conservative max of Record/Envoy egress bytes and flow-feed bytes.");
        }

        public ByteInspection withCoverage(Coverage coverage) {
            if ("VERIFIED".equals(coverage.status()) || !"VERIFIED".equals(status)) {
                return this;
            }
            return new ByteInspection("UNVERIFIED", inspectedBytes, egressedBytes,
                    flowBytes, uninspectedBytes, null, recordsMissingByteCounts,
                    "Inspected-byte percentage is withheld because evidence coverage is UNVERIFIED.");
        }
    }

    public record EdmEventSummary(String registry, long events, Long distinctMatches,
                                  long blockEvents, long flagEvents, String note) {
    }

    public record RegistryStaleness(String status, List<RegistryStalenessEntry> registries,
                                    String note) {
        public RegistryStaleness {
            registries = registries == null ? List.of() : List.copyOf(registries);
        }

        public static RegistryStaleness unverified(String note) {
            return new RegistryStaleness("UNVERIFIED", List.of(), note);
        }
    }

    public record RegistryStalenessEntry(String registry, long distinctFingerprints,
                                         String sourceTimestamp, Long ageSeconds,
                                         String source) {
    }

    /**
     * Aggregate {@code rows} (already filtered to the window) into a report. The chain
     * result is computed over the whole chain (integrity is global) and passed in.
     */
    public static ReportModel build(String generatedAt, String windowFrom, String windowTo,
                                    java.util.List<RecordRow> rows, ChainVerifier.Result chain,
                                    Coverage coverage) {
        return build(generatedAt, windowFrom, windowTo, rows, chain, coverage,
                ByteInspection.fromCoverage(coverage, null),
                RegistryStaleness.unverified("No EDM registry directory supplied; staleness cannot be verified."),
                "UNVERIFIED", ContinuationAttestation.evaluate(rows, rows, List.of(), null));
    }

    public static ReportModel build(String generatedAt, String windowFrom, String windowTo,
                                    java.util.List<RecordRow> rows, ChainVerifier.Result chain,
                                    Coverage coverage, ByteInspection inspectedBytes,
                                    RegistryStaleness registryStaleness,
                                    String coveredPopulation) {
        return build(generatedAt, windowFrom, windowTo, rows, chain, coverage,
                inspectedBytes, registryStaleness, coveredPopulation,
                ContinuationAttestation.evaluate(rows, rows, List.of(), null));
    }

    public static ReportModel build(String generatedAt, String windowFrom, String windowTo,
                                    java.util.List<RecordRow> rows, ChainVerifier.Result chain,
                                    Coverage coverage, ByteInspection inspectedBytes,
                                    RegistryStaleness registryStaleness,
                                    String coveredPopulation,
                                    ContinuationAttestation.Summary safeContinuation) {
        ContinuationAttestation.Summary effectiveContinuation = safeContinuation == null
                ? ContinuationAttestation.Summary.empty() : safeContinuation;
        if (!chain.ok()) {
            effectiveContinuation = effectiveContinuation.withCoverageGap(
                    "turn-record-integrity-invalid", 1);
        }
        Coverage effectiveCoverage = coverage.withEvidenceGaps(
                effectiveContinuation.coverageGaps());
        ByteInspection effectiveInspection = inspectedBytes.withCoverage(effectiveCoverage);
        Map<String, Long> byRule = new TreeMap<>();
        Map<String, Long> byAction = new TreeMap<>();
        Map<String, Long> postures = new TreeMap<>();
        Map<String, Long> fingerprints = new TreeMap<>();
        Map<String, MutableEdmSummary> edm = new TreeMap<>();
        long blocks = 0;
        for (RecordRow row : rows) {
            if ("BLOCK".equals(row.action())) {
                blocks++;
            }
            postures.merge(row.posture() == null ? "unknown" : row.posture(), 1L, Long::sum);
            fingerprints.merge(
                    row.configFingerprint() == null ? "unknown" : row.configFingerprint(),
                    1L, Long::sum);
            for (Finding f : row.findings()) {
                byRule.merge(f.rule(), 1L, Long::sum);
                byAction.merge(f.action().name(), 1L, Long::sum);
                if (f.rule().startsWith("edm-")) {
                    String registry = f.rule().substring("edm-".length());
                    if (!row.edmEvents().containsKey(registry)) {
                        edm.computeIfAbsent(registry, MutableEdmSummary::new)
                                .addUnknown(f.action().name());
                    }
                }
            }
            for (RecordRow.EdmEvent event : row.edmEvents().values()) {
                edm.computeIfAbsent(event.registry(), MutableEdmSummary::new)
                        .addKnown(event.distinctCount(), event.action());
            }
        }
        Map<String, EdmEventSummary> edmSummaries = new LinkedHashMap<>();
        edm.forEach((registry, summary) -> edmSummaries.put(registry, summary.toSummary()));
        // Deterministic ordering for stable JSON/HTML output.
        return new ReportModel(SCHEMA_VERSION, generatedAt, windowFrom, windowTo,
                rows.size(), new LinkedHashMap<>(byRule), new LinkedHashMap<>(byAction),
                blocks, new LinkedHashMap<>(postures), new LinkedHashMap<>(fingerprints),
                chain, effectiveCoverage, effectiveInspection, edmSummaries,
                registryStaleness, coveredPopulation, effectiveContinuation);
    }

    private static final class MutableEdmSummary {
        private final String registry;
        private long events;
        private long distinctMatches;
        private boolean unknown;
        private long blockEvents;
        private long flagEvents;

        private MutableEdmSummary(String registry) {
            this.registry = registry;
        }

        void addKnown(long distinctCount, String action) {
            events++;
            distinctMatches += Math.max(0, distinctCount);
            addAction(action);
        }

        void addUnknown(String action) {
            events++;
            unknown = true;
            addAction(action);
        }

        private void addAction(String action) {
            if ("BLOCK".equals(action)) {
                blockEvents++;
            } else {
                flagEvents++;
            }
        }

        EdmEventSummary toSummary() {
            Long count = unknown ? null : distinctMatches;
            String note = unknown
                    ? "One or more EDM Findings predate distinct-count recording; count is UNVERIFIED."
                    : "Distinct matches are counted per Turn and summed across events.";
            return new EdmEventSummary(registry, events, count, blockEvents, flagEvents, note);
        }
    }
}
