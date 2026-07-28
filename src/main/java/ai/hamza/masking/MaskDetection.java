package ai.hamza.masking;

import ai.hamza.policy.DetectionRun;
import ai.hamza.policy.Finding;

import java.util.List;
import java.util.Map;

/** Transient complete secret+EDM scan over Adapter-approved decoded segments. */
public record MaskDetection(
        List<DetectionRun> runs,
        List<MaskCandidate> candidates,
        List<Finding> findings,
        List<String> blockingRules,
        Map<String, Integer> edmDistinctCounts,
        boolean complete,
        boolean unreliableEnforcingFinding) {

    public MaskDetection {
        runs = runs == null ? List.of() : List.copyOf(runs);
        candidates = candidates == null ? List.of() : List.copyOf(candidates);
        findings = findings == null ? List.of() : List.copyOf(findings);
        blockingRules = blockingRules == null ? List.of() : List.copyOf(blockingRules);
        edmDistinctCounts = edmDistinctCounts == null
                ? Map.of() : Map.copyOf(edmDistinctCounts);
    }
}
