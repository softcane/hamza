package ai.hamza.attest;

import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Content-free Safe Continuation evidence accounting. The module uses opaque recovery
 * ids only while joining Records in memory; its result exposes counts and fixed gap
 * classes, never ids, bodies, Fingerprints, substitutes, field ids, or mappings.
 */
public final class ContinuationAttestation {

    // Indices into the mutable counters[] box threaded through the window-accounting
    // phase methods below. A plain array (rather than a dozen local long variables or
    // a new holder type) lets those phase methods mutate the running totals in place.
    private static final int C_ELIGIBLE = 0;
    private static final int C_ATTEMPTED = 1;
    private static final int C_DELIVERED = 2;
    private static final int C_REJECTED = 3;
    private static final int C_FAILED_CLOSED = 4;
    private static final int C_SOURCE_BLOCKS = 5;
    private static final int C_SOURCE_MASKS = 6;
    private static final int C_DERIVED_FLAGS = 7;
    private static final int C_LINKED_PAIRS = 8;
    private static final int C_WITHHELD = 9;
    private static final int C_TRANSFORMED_INSPECTED = 10;
    private static final int C_TRANSFORMED_EGRESSED = 11;
    private static final int COUNTER_SLOTS = 12;

    private ContinuationAttestation() {
    }

    public record Summary(
            long recoveryScopes,
            long eligible,
            long attempted,
            long delivered,
            long rejected,
            long failedClosed,
            long completed,
            long failed,
            long fallback,
            long sourceBlockTurns,
            long sourceMaskTurns,
            long derivedFlagTurns,
            long linkedPairs,
            long originalBytesWithheld,
            long transformedBytesInspected,
            long transformedBytesEgressed,
            Map<String, Long> turnsByAgent,
            Map<String, Long> turnsByProvider,
            Map<String, Long> outcomesByAgentVersion,
            Map<String, Long> outcomesByStatus,
            Map<String, Long> recipeVersions,
            Map<String, Long> workflowProfileVersions,
            Map<String, Long> coverageGaps,
            OutcomeIntegrity outcomeIntegrity) {

        public Summary {
            turnsByAgent = immutableSorted(turnsByAgent);
            turnsByProvider = immutableSorted(turnsByProvider);
            outcomesByAgentVersion = immutableSorted(outcomesByAgentVersion);
            outcomesByStatus = immutableSorted(outcomesByStatus);
            recipeVersions = immutableSorted(recipeVersions);
            workflowProfileVersions = immutableSorted(workflowProfileVersions);
            coverageGaps = immutableSorted(coverageGaps);
            outcomeIntegrity = outcomeIntegrity == null ? OutcomeIntegrity.notAvailable()
                    : outcomeIntegrity;
        }

        public static Summary empty() {
            return new Summary(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), Map.of(),
                    OutcomeIntegrity.notApplicable());
        }

        public Summary withCoverageGap(String kind, long count) {
            if (kind == null || kind.isBlank() || count <= 0) {
                return this;
            }
            Map<String, Long> merged = new TreeMap<>(coverageGaps);
            merged.merge(kind, count, Long::sum);
            return new Summary(recoveryScopes, eligible, attempted, delivered, rejected,
                    failedClosed, completed, failed, fallback, sourceBlockTurns,
                    sourceMaskTurns, derivedFlagTurns, linkedPairs, originalBytesWithheld,
                    transformedBytesInspected, transformedBytesEgressed,
                    turnsByAgent, turnsByProvider, outcomesByAgentVersion,
                    outcomesByStatus, recipeVersions, workflowProfileVersions,
                    merged, outcomeIntegrity);
        }

        @Override
        public String toString() {
            return "ContinuationAttestation.Summary[recoveryScopes=" + recoveryScopes
                    + ", attempted=" + attempted + ", delivered=" + delivered
                    + ", coverageGapKinds=" + coverageGaps.size() + "]";
        }
    }

    public record OutcomeIntegrity(String status, long entries, Long firstBrokenSeq,
                                   String detail, String headHash, long integrityGaps) {
        public static OutcomeIntegrity from(RecoveryOutcomeChainVerifier.Result result) {
            if (result == null) {
                return notAvailable();
            }
            return new OutcomeIntegrity(result.ok() ? "OK" : "BROKEN", result.entries(),
                    result.firstBrokenSeq() < 0 ? null : result.firstBrokenSeq(),
                    boundedDetail(result.detail()), result.headHash(), result.integrityGaps());
        }

        public static OutcomeIntegrity notAvailable() {
            return notAvailable(0);
        }

        public static OutcomeIntegrity notAvailable(long entries) {
            return notAvailable(entries, 0);
        }

        public static OutcomeIntegrity notAvailable(long entries, long integrityGaps) {
            return new OutcomeIntegrity("UNVERIFIED", Math.max(0, entries), null,
                    "Recovery Outcome verification was not available.", null,
                    Math.max(0, integrityGaps));
        }

        public static OutcomeIntegrity notApplicable() {
            return new OutcomeIntegrity("N/A", 0, null,
                    "No Safe Continuation evidence in this window.", null, 0);
        }

        @Override
        public String toString() {
            return "OutcomeIntegrity[status=" + status + ", entries=" + entries
                    + ", integrityGaps=" + integrityGaps + "]";
        }
    }

    /**
     * Evaluate window accounting while resolving parent/outcome links against the full
     * Record set. This avoids manufacturing a gap when a linked item sits just outside
     * the report window.
     */
    public static Summary evaluate(List<RecordRow> windowRows,
                                   List<RecordRow> allRows,
                                   List<RecoveryOutcomeRow> allOutcomes,
                                   RecoveryOutcomeChainVerifier.Result outcomeChain) {
        return evaluate(windowRows, allRows, allOutcomes, outcomeChain,
                outcomeChain == null ? 0 : outcomeChain.integrityGaps());
    }

    public static Summary evaluate(List<RecordRow> windowRows,
                                   List<RecordRow> allRows,
                                   List<RecoveryOutcomeRow> allOutcomes,
                                   RecoveryOutcomeChainVerifier.Result outcomeChain,
                                   long knownOutcomeIntegrityGaps) {
        List<RecordRow> window = List.copyOf(windowRows == null ? List.of() : windowRows);
        List<RecordRow> all = List.copyOf(allRows == null ? List.of() : allRows);
        List<RecoveryOutcomeRow> outcomes = List.copyOf(
                allOutcomes == null ? List.of() : allOutcomes);
        Map<String, Long> gaps = new TreeMap<>();

        Map<String, RecordRow> allByTurnId = new HashMap<>();
        Map<String, List<RecordRow>> derivedByParent = new HashMap<>();
        Map<String, List<RecordRow>> sourcesByRecovery = new HashMap<>();
        Map<String, List<RecordRow>> derivedByRecovery = new HashMap<>();
        buildRecordIndices(all, allByTurnId, derivedByParent, sourcesByRecovery, derivedByRecovery);

        Map<String, List<RecoveryOutcomeRow>> outcomesByRecovery = new HashMap<>();
        indexOutcomesByRecovery(outcomes, outcomesByRecovery);
        boolean outcomesVerified = outcomeChain != null && outcomeChain.ok();

        Set<String> recoveryScopes = new HashSet<>();
        Set<String> outcomeExpectedScopes = new HashSet<>();
        Map<String, Long> outcomeStatuses = new TreeMap<>();
        Map<String, Long> turnsByAgent = new TreeMap<>();
        Map<String, Long> turnsByProvider = new TreeMap<>();
        Map<String, Long> outcomeAgentVersions = new TreeMap<>();
        Map<String, Long> recipeVersions = new TreeMap<>();
        Map<String, Long> profileVersions = new TreeMap<>();
        Set<String> safetyValidated = new HashSet<>();
        long[] counters = new long[COUNTER_SLOTS];

        accountForWindow(window, allByTurnId, derivedByParent, recoveryScopes,
                outcomeExpectedScopes, turnsByAgent, turnsByProvider, recipeVersions,
                profileVersions, safetyValidated, gaps, counters);

        reconcileOutcomeStatuses(outcomeExpectedScopes, outcomesByRecovery, sourcesByRecovery,
                derivedByRecovery, derivedByParent, allByTurnId, outcomesVerified,
                outcomeStatuses, outcomeAgentVersions, gaps);

        validateGlobalOutcomeLinkage(outcomes, recoveryScopes, sourcesByRecovery,
                derivedByRecovery, gaps);

        OutcomeIntegrity integrity = computeOutcomeIntegrity(outcomeExpectedScopes, outcomes,
                outcomeChain, knownOutcomeIntegrityGaps, gaps);

        long completed = outcomeStatuses.getOrDefault("completed", 0L);
        long failed = outcomeStatuses.getOrDefault("failed", 0L);
        long fallback = outcomeStatuses.getOrDefault("human-fallback", 0L);
        return new Summary(recoveryScopes.size(), counters[C_ELIGIBLE], counters[C_ATTEMPTED],
                counters[C_DELIVERED], counters[C_REJECTED], counters[C_FAILED_CLOSED],
                completed, failed, fallback, counters[C_SOURCE_BLOCKS], counters[C_SOURCE_MASKS],
                counters[C_DERIVED_FLAGS], counters[C_LINKED_PAIRS], counters[C_WITHHELD],
                counters[C_TRANSFORMED_INSPECTED], counters[C_TRANSFORMED_EGRESSED],
                turnsByAgent, turnsByProvider, outcomeAgentVersions, outcomeStatuses,
                recipeVersions, profileVersions, gaps, integrity);
    }

    /** Single pass over every Record building the four in-memory join indices. */
    private static void buildRecordIndices(List<RecordRow> all,
                                           Map<String, RecordRow> allByTurnId,
                                           Map<String, List<RecordRow>> derivedByParent,
                                           Map<String, List<RecordRow>> sourcesByRecovery,
                                           Map<String, List<RecordRow>> derivedByRecovery) {
        for (RecordRow row : all) {
            if (row.turnId() != null) {
                allByTurnId.put(row.turnId(), row);
            }
            if (isRole(row, "SOURCE") && hasText(row.continuation().recoveryId())) {
                sourcesByRecovery.computeIfAbsent(row.continuation().recoveryId(), ignored ->
                        new ArrayList<>()).add(row);
            } else if (isRole(row, "DERIVED")) {
                if (hasText(row.continuation().parentTurnId())) {
                    derivedByParent.computeIfAbsent(row.continuation().parentTurnId(), ignored ->
                            new ArrayList<>()).add(row);
                }
                if (hasText(row.continuation().recoveryId())) {
                    derivedByRecovery.computeIfAbsent(row.continuation().recoveryId(), ignored ->
                            new ArrayList<>()).add(row);
                }
            }
        }
    }

    private static void indexOutcomesByRecovery(List<RecoveryOutcomeRow> outcomes,
            Map<String, List<RecoveryOutcomeRow>> outcomesByRecovery) {
        for (RecoveryOutcomeRow outcome : outcomes) {
            if (hasText(outcome.recoveryId())) {
                outcomesByRecovery.computeIfAbsent(outcome.recoveryId(), ignored ->
                        new ArrayList<>()).add(outcome);
            }
        }
    }

    /** Dispatches each window row to its role-specific accounting phase. */
    private static void accountForWindow(List<RecordRow> window,
            Map<String, RecordRow> allByTurnId,
            Map<String, List<RecordRow>> derivedByParent,
            Set<String> recoveryScopes,
            Set<String> outcomeExpectedScopes,
            Map<String, Long> turnsByAgent,
            Map<String, Long> turnsByProvider,
            Map<String, Long> recipeVersions,
            Map<String, Long> profileVersions,
            Set<String> safetyValidated,
            Map<String, Long> gaps,
            long[] counters) {
        for (RecordRow row : window) {
            validateEvidenceSafety(row, gaps, safetyValidated);
            if (isRole(row, "SOURCE")) {
                accountForSourceRow(row, derivedByParent, recoveryScopes, outcomeExpectedScopes,
                        turnsByAgent, turnsByProvider, recipeVersions, profileVersions,
                        safetyValidated, gaps, counters);
            } else if (isRole(row, "DERIVED")) {
                accountForDerivedRow(row, allByTurnId, recoveryScopes, turnsByAgent,
                        turnsByProvider, safetyValidated, gaps, counters);
            } else {
                accountForSimulatedRow(row, turnsByAgent, turnsByProvider, gaps, counters);
            }
        }
    }

    private static void accountForSourceRow(RecordRow row,
            Map<String, List<RecordRow>> derivedByParent,
            Set<String> recoveryScopes,
            Set<String> outcomeExpectedScopes,
            Map<String, Long> turnsByAgent,
            Map<String, Long> turnsByProvider,
            Map<String, Long> recipeVersions,
            Map<String, Long> profileVersions,
            Set<String> safetyValidated,
            Map<String, Long> gaps,
            long[] counters) {
        addBoundedValue(turnsByAgent, row.agent(), gaps);
        addBoundedValue(turnsByProvider, row.provider(), gaps);
        counters[C_ATTEMPTED]++;
        String recoveryId = row.continuation().recoveryId();
        if (hasText(recoveryId)) {
            recoveryScopes.add(recoveryId);
        } else {
            gap(gaps, "source-linkage-missing");
        }
        String reason = row.continuation().reasonCode();
        boolean eligibleReason = "eligible-edm".equals(reason)
                || "masked-secret-edm".equals(reason);
        if (eligibleReason) {
            counters[C_ELIGIBLE]++;
            if (hasText(recoveryId)) {
                outcomeExpectedScopes.add(recoveryId);
            }
        } else if (reason != null && reason.startsWith("ineligible-")) {
            counters[C_REJECTED]++;
        } else {
            counters[C_FAILED_CLOSED]++;
        }
        if ("BLOCK".equals(row.action())) {
            counters[C_SOURCE_BLOCKS]++;
        } else if (isValidMaskedSource(row)) {
            counters[C_SOURCE_MASKS]++;
        }
        Long sourceWithheld = row.continuation().requestBytesWithheld();
        if (sourceWithheld != null) {
            counters[C_WITHHELD] = add(counters[C_WITHHELD], sourceWithheld, gaps);
        }
        if (eligibleReason) {
            List<RecordRow> children = derivedByParent.getOrDefault(row.turnId(), List.of());
            if (children.isEmpty()) {
                gap(gaps, "missing-derived-record");
            } else if (children.size() > 1) {
                gap(gaps, "duplicate-derived-record");
            }
            for (RecordRow child : children) {
                validateEvidenceSafety(child, gaps, safetyValidated);
                if (!same(row.continuation().recoveryId(), child.continuation().recoveryId())) {
                    gap(gaps, "derived-parent-link-invalid");
                }
            }
        }
        addVersion(recipeVersions, row.continuation().recipeId(),
                row.continuation().recipeVersion(), gaps);
        addVersion(profileVersions, row.continuation().workflowProfileId(),
                row.continuation().workflowProfileVersion(), gaps);
    }

    private static void accountForDerivedRow(RecordRow row,
            Map<String, RecordRow> allByTurnId,
            Set<String> recoveryScopes,
            Map<String, Long> turnsByAgent,
            Map<String, Long> turnsByProvider,
            Set<String> safetyValidated,
            Map<String, Long> gaps,
            long[] counters) {
        addBoundedValue(turnsByAgent, row.agent(), gaps);
        addBoundedValue(turnsByProvider, row.provider(), gaps);
        counters[C_DELIVERED]++;
        String recoveryId = row.continuation().recoveryId();
        if (hasText(recoveryId)) {
            recoveryScopes.add(recoveryId);
        } else {
            gap(gaps, "derived-linkage-missing");
        }
        boolean flagOnly = "FLAG".equals(row.action())
                && row.findings().stream().allMatch(finding -> finding.action() == Action.FLAG);
        if (flagOnly) {
            counters[C_DERIVED_FLAGS]++;
        }
        RecordRow parent = allByTurnId.get(row.continuation().parentTurnId());
        if (parent == null || !isRole(parent, "SOURCE")) {
            gap(gaps, "missing-source-record");
        } else if (!same(parent.continuation().recoveryId(), recoveryId)) {
            gap(gaps, "derived-parent-link-invalid");
        } else {
            counters[C_LINKED_PAIRS]++;
            validateEvidenceSafety(parent, gaps, safetyValidated);
        }
        if (row.requestBytesInspected() != null && row.requestBytesEgressed() != null) {
            counters[C_TRANSFORMED_INSPECTED] = add(counters[C_TRANSFORMED_INSPECTED],
                    row.requestBytesInspected(), gaps);
            counters[C_TRANSFORMED_EGRESSED] = add(counters[C_TRANSFORMED_EGRESSED],
                    row.requestBytesEgressed(), gaps);
        }
    }

    private static void accountForSimulatedRow(RecordRow row,
            Map<String, Long> turnsByAgent,
            Map<String, Long> turnsByProvider,
            Map<String, Long> gaps,
            long[] counters) {
        boolean simulated = false;
        for (Finding finding : row.findings()) {
            if ("continuation-simulation-eligible".equals(finding.rule())) {
                counters[C_ELIGIBLE]++;
                simulated = true;
            } else if (finding.rule().startsWith("continuation-simulation-ineligible-")) {
                counters[C_REJECTED]++;
                simulated = true;
            } else if ("continuation-simulation-scan-incomplete".equals(finding.rule())) {
                simulated = true;
            }
        }
        if (simulated) {
            counters[C_ATTEMPTED]++;
            addBoundedValue(turnsByAgent, row.agent(), gaps);
            addBoundedValue(turnsByProvider, row.provider(), gaps);
        }
    }

    private static void reconcileOutcomeStatuses(
            Set<String> outcomeExpectedScopes,
            Map<String, List<RecoveryOutcomeRow>> outcomesByRecovery,
            Map<String, List<RecordRow>> sourcesByRecovery,
            Map<String, List<RecordRow>> derivedByRecovery,
            Map<String, List<RecordRow>> derivedByParent,
            Map<String, RecordRow> allByTurnId,
            boolean outcomesVerified,
            Map<String, Long> outcomeStatuses,
            Map<String, Long> outcomeAgentVersions,
            Map<String, Long> gaps) {
        for (String recoveryId : outcomeExpectedScopes) {
            List<RecoveryOutcomeRow> scoped = outcomesByRecovery.getOrDefault(
                    recoveryId, List.of());
            if (scoped.isEmpty()) {
                gap(gaps, "missing-recovery-outcome");
            }
            if (scoped.size() > 1) {
                gap(gaps, "duplicate-recovery-outcome");
            }
            for (RecoveryOutcomeRow outcome : scoped) {
                boolean completeLink = hasCompleteLink(recoveryId, sourcesByRecovery,
                        derivedByRecovery, derivedByParent, allByTurnId);
                String status = outcomesVerified && completeLink
                        ? boundedOutcomeStatus(outcome.status(), gaps) : "unverified";
                outcomeStatuses.merge(status, 1L, Long::sum);
                if (outcomesVerified && completeLink) {
                    addBoundedValue(outcomeAgentVersions,
                            outcome.agent() + ":" + outcome.agentVersion(), gaps);
                }
            }
        }
    }

    /**
     * Outcome evidence must itself have both sides of the causal link. Validate this
     * globally because the outcome chain is global, even for a narrow window.
     */
    private static void validateGlobalOutcomeLinkage(List<RecoveryOutcomeRow> outcomes,
            Set<String> recoveryScopes,
            Map<String, List<RecordRow>> sourcesByRecovery,
            Map<String, List<RecordRow>> derivedByRecovery,
            Map<String, Long> gaps) {
        for (RecoveryOutcomeRow outcome : outcomes) {
            if (recoveryScopes.contains(outcome.recoveryId())) {
                continue; // window-side source/derived validation already counted this gap
            }
            if (sourcesByRecovery.getOrDefault(outcome.recoveryId(), List.of()).isEmpty()) {
                gap(gaps, "missing-source-record");
            }
            if (derivedByRecovery.getOrDefault(outcome.recoveryId(), List.of()).isEmpty()) {
                gap(gaps, "missing-derived-record");
            }
        }
    }

    private static OutcomeIntegrity computeOutcomeIntegrity(
            Set<String> outcomeExpectedScopes,
            List<RecoveryOutcomeRow> outcomes,
            RecoveryOutcomeChainVerifier.Result outcomeChain,
            long knownOutcomeIntegrityGaps,
            Map<String, Long> gaps) {
        OutcomeIntegrity integrity = outcomeExpectedScopes.isEmpty() && outcomes.isEmpty()
                ? OutcomeIntegrity.notApplicable()
                : outcomeChain == null ? OutcomeIntegrity.notAvailable(
                        outcomes.size(), knownOutcomeIntegrityGaps)
                : OutcomeIntegrity.from(outcomeChain);
        if (!outcomeExpectedScopes.isEmpty() || !outcomes.isEmpty()) {
            if (outcomeChain == null) {
                gap(gaps, "recovery-outcome-verification-unavailable");
            } else if (!outcomeChain.ok()) {
                gap(gaps, "recovery-outcome-integrity-invalid");
            }
            if (knownOutcomeIntegrityGaps > 0 && (outcomeChain == null || outcomeChain.ok())) {
                gap(gaps, "recovery-outcome-integrity-invalid");
            }
        }
        return integrity;
    }

    private static boolean isRole(RecordRow row, String role) {
        return row != null && row.continuation() != null
                && role.equals(row.continuation().role());
    }

    private static boolean hasCompleteLink(
            String recoveryId,
            Map<String, List<RecordRow>> sourcesByRecovery,
            Map<String, List<RecordRow>> derivedByRecovery,
            Map<String, List<RecordRow>> derivedByParent,
            Map<String, RecordRow> allByTurnId) {
        List<RecordRow> sources = sourcesByRecovery.getOrDefault(recoveryId, List.of());
        List<RecordRow> derived = derivedByRecovery.getOrDefault(recoveryId, List.of());
        if (sources.isEmpty() || derived.isEmpty()) {
            return false;
        }
        for (RecordRow source : sources) {
            List<RecordRow> children = derivedByParent.getOrDefault(source.turnId(), List.of());
            if (children.size() != 1
                    || !same(recoveryId, children.getFirst().continuation().recoveryId())) {
                return false;
            }
        }
        for (RecordRow child : derived) {
            RecordRow parent = allByTurnId.get(child.continuation().parentTurnId());
            if (parent == null || !isRole(parent, "SOURCE")
                    || !same(recoveryId, parent.continuation().recoveryId())) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasScanIncomplete(RecordRow row) {
        return row.findings().stream().map(Finding::rule)
                .anyMatch("scan-incomplete"::equals);
    }

    private static String boundedOutcomeStatus(String status, Map<String, Long> gaps) {
        if ("completed".equals(status) || "failed".equals(status)
                || "human-fallback".equals(status)) {
            return status;
        }
        gap(gaps, "recovery-outcome-invalid");
        return "invalid";
    }

    private static void addVersion(Map<String, Long> target, String id, Integer version,
                                   Map<String, Long> gaps) {
        if (isBoundedId(id) && version != null && version > 0) {
            target.merge(id + ":" + version, 1L, Long::sum);
        } else {
            gap(gaps, "continuation-metadata-invalid");
        }
    }

    private static void addBoundedValue(Map<String, Long> target, String value,
                                        Map<String, Long> gaps) {
        if (isBoundedId(value)) {
            target.merge(value, 1L, Long::sum);
        } else {
            gap(gaps, "continuation-metadata-invalid");
        }
    }

    private static void validateEvidenceSafety(RecordRow row, Map<String, Long> gaps,
                                               Set<String> validated) {
        String key = row.turnId() == null ? "seq:" + row.seq() : "turn:" + row.turnId();
        if (!validated.add(key)) {
            return;
        }
        if (hasScanIncomplete(row)) {
            gap(gaps, "scan-incomplete");
        }
        if (isRole(row, "SOURCE")) {
            if ("MASK".equals(row.action())) {
                if (row.continuation().maskedValueCount() == null
                        || row.continuation().maskedValueCount() <= 0) {
                    gap(gaps, "source-mask-count-invalid");
                }
                if (row.findings().isEmpty()
                        || row.findings().stream().anyMatch(
                                finding -> finding.action() != Action.MASK)) {
                    gap(gaps, "source-not-mask-only");
                }
            } else if (!"BLOCK".equals(row.action())) {
                gap(gaps, "source-not-block");
            }
            Long egressed = row.requestBytesEgressed();
            if (egressed == null) {
                gap(gaps, "source-egress-unverified");
            } else if (egressed != 0) {
                gap(gaps, "source-nonzero-egress");
            }
            Long received = row.requestBytesReceived();
            Long inspected = row.requestBytesInspected();
            Long withheld = row.continuation().requestBytesWithheld();
            if (received == null || inspected == null || withheld == null) {
                gap(gaps, "source-byte-accounting-missing");
            } else if (!received.equals(inspected) || !received.equals(withheld)) {
                gap(gaps, "source-byte-accounting-invalid");
            }
        } else if (isRole(row, "DERIVED")) {
            if (!"FLAG".equals(row.action())
                    || row.findings().stream().anyMatch(finding -> finding.action() != Action.FLAG)) {
                gap(gaps, "derived-not-flag-only");
            }
            Long received = row.requestBytesReceived();
            Long inspected = row.requestBytesInspected();
            Long egressed = row.requestBytesEgressed();
            if (received == null || inspected == null || egressed == null) {
                gap(gaps, "derived-byte-accounting-missing");
            } else if (!received.equals(inspected) || !inspected.equals(egressed)) {
                gap(gaps, "derived-byte-accounting-invalid");
            }
        }
    }

    private static long add(long current, long value, Map<String, Long> gaps) {
        if (value < 0) {
            gap(gaps, "byte-accounting-invalid");
            return current;
        }
        try {
            return Math.addExact(current, value);
        } catch (ArithmeticException overflow) {
            gap(gaps, "byte-accounting-overflow");
            return Long.MAX_VALUE;
        }
    }

    private static boolean isValidMaskedSource(RecordRow row) {
        return "MASK".equals(row.action())
                && row.continuation().maskedValueCount() != null
                && row.continuation().maskedValueCount() > 0
                && !row.findings().isEmpty()
                && row.findings().stream().allMatch(finding -> finding.action() == Action.MASK);
    }

    private static void gap(Map<String, Long> gaps, String kind) {
        gaps.merge(kind, 1L, Long::sum);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static boolean isBoundedId(String value) {
        return value != null
                && value.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    }

    private static boolean same(String left, String right) {
        return left != null && left.equals(right);
    }

    private static String boundedDetail(String detail) {
        if (detail == null) {
            return null;
        }
        return detail.length() <= 256 ? detail : detail.substring(0, 256);
    }

    private static Map<String, Long> immutableSorted(Map<String, Long> source) {
        return Collections.unmodifiableMap(new LinkedHashMap<>(new TreeMap<>(
                source == null ? Map.of() : source)));
    }
}
