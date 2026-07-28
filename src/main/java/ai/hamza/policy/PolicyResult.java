package ai.hamza.policy;

import ai.hamza.edm.EdmScanExhaustionReason;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The outcome of evaluating Egress against the policy (CONTEXT: the resolved Action
 * for a Turn's Findings).
 *
 * @param findings        all Findings (rule + Action), content-free
 * @param effectiveAction the most severe Action across findings (BLOCK &gt; MASK &gt; FLAG);
 *                        {@link Action#FLAG} when there are no findings
 * @param maskedBody    the mutated body, present iff {@code effectiveAction == MASK}
 * @param blockingRules   the rules that triggered a BLOCK (for {@code hamza_egress_blocked_total})
 * @param edmDistinctCounts registry name → distinct EDM fingerprint matches for this Turn
 *                          or scan window; counts only, never matched values
 */
public record PolicyResult(
        List<Finding> findings,
        Action effectiveAction,
        Optional<byte[]> maskedBody,
        List<String> blockingRules,
        Map<String, Integer> edmDistinctCounts,
        boolean edmScanComplete,
        Optional<EdmScanExhaustionReason> edmScanExhaustionReason,
        List<DetectionRun> detectionRuns) {

    public PolicyResult(List<Finding> findings, Action effectiveAction,
                        Optional<byte[]> maskedBody, List<String> blockingRules,
                        Map<String, Integer> edmDistinctCounts) {
        this(findings, effectiveAction, maskedBody, blockingRules, edmDistinctCounts,
                true, Optional.empty(), List.of());
    }

    public PolicyResult(List<Finding> findings, Action effectiveAction,
                        Optional<byte[]> maskedBody, List<String> blockingRules,
                        Map<String, Integer> edmDistinctCounts, boolean edmScanComplete,
                        Optional<EdmScanExhaustionReason> edmScanExhaustionReason) {
        this(findings, effectiveAction, maskedBody, blockingRules, edmDistinctCounts,
                edmScanComplete, edmScanExhaustionReason, List.of());
    }

    public PolicyResult(List<Finding> findings, Action effectiveAction,
                        Optional<byte[]> maskedBody, List<String> blockingRules) {
        this(findings, effectiveAction, maskedBody, blockingRules, Map.of(),
                true, Optional.empty(), List.of());
    }

    public PolicyResult {
        findings = findings == null ? List.of() : List.copyOf(findings);
        blockingRules = blockingRules == null ? List.of() : List.copyOf(blockingRules);
        edmDistinctCounts = edmDistinctCounts == null ? Map.of() : Map.copyOf(edmDistinctCounts);
        edmScanExhaustionReason = edmScanExhaustionReason == null
                ? Optional.empty() : edmScanExhaustionReason;
        detectionRuns = detectionRuns == null ? List.of() : List.copyOf(detectionRuns);
        if (edmScanComplete != edmScanExhaustionReason.isEmpty()) {
            throw new IllegalArgumentException("invalid EDM scan completeness");
        }
    }

    public boolean isBlock() {
        return effectiveAction == Action.BLOCK;
    }

    public boolean isMask() {
        return effectiveAction == Action.MASK && maskedBody.isPresent();
    }

    public boolean hasFindings() {
        return !findings.isEmpty();
    }

    public static PolicyResult clean() {
        return new PolicyResult(List.of(), Action.FLAG, Optional.empty(), List.of());
    }

    public static PolicyResult clean(List<DetectionRun> runs) {
        return new PolicyResult(List.of(), Action.FLAG, Optional.empty(), List.of(), Map.of(),
                true, Optional.empty(), runs);
    }

    public List<DetectorRunEvidence> detectorEvidence() {
        return detectionRuns.stream().map(DetectionRun::evidence).toList();
    }
}
