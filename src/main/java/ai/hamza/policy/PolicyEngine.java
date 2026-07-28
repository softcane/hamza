package ai.hamza.policy;

import ai.hamza.config.HamzaProperties;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.edm.EdmCountScanResult;
import ai.hamza.edm.EdmScanExhaustionReason;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Runs the {@link SecretDetector} over the outbound <strong>body only</strong> and maps
 * matches to an {@link Action} per rule from config. Default Posture is
 * {@link Action#FLAG} (observe before enforce).
 *
 * <p>Invariant: detection is scoped to the body. Provider-auth headers
 * (Authorization, …) are never passed here, never scanned, never a Finding.
 */
@Component
public class PolicyEngine {

    private final SecretDetector detector;
    private final Masker masker;
    private final Action posture;
    private final Map<String, Action> ruleActions;
    private final EdmMatcher edmMatcher;
    private final int edmBlockThreshold;

    @Autowired
    public PolicyEngine(SecretDetector detector, Masker masker, HamzaProperties properties,
                        EdmMatcher edmMatcher) {
        this(detector, masker, properties.policy().posture(), properties.policy().ruleActions(),
                edmMatcher, properties.edm().blockThreshold());
    }

    /** Direct constructor for tests with explicit policy config (EDM disabled). */
    public PolicyEngine(SecretDetector detector, Masker masker, Action posture,
                        Map<String, Action> ruleActions) {
        this(detector, masker, posture, ruleActions, null,
                HamzaProperties.DEFAULT_EDM_BLOCK_THRESHOLD);
    }

    /** Direct constructor for tests with explicit EDM config. */
    public PolicyEngine(SecretDetector detector, Masker masker, Action posture,
                        Map<String, Action> ruleActions, EdmMatcher edmMatcher,
                        int edmBlockThreshold) {
        this.detector = detector;
        this.masker = masker;
        this.posture = posture == null ? Action.FLAG : posture;
        this.ruleActions = ruleActions == null ? Map.of() : Map.copyOf(ruleActions);
        this.edmMatcher = edmMatcher;
        this.edmBlockThreshold = edmBlockThreshold > 0 ? edmBlockThreshold
                : HamzaProperties.DEFAULT_EDM_BLOCK_THRESHOLD;
    }

    /** Evaluate the outbound body. Never receives or inspects headers. */
    public PolicyResult evaluate(byte[] body) {
        if (body == null || body.length == 0) {
            return PolicyResult.clean(List.of(emptySecretRun(), disabledEdmRun()));
        }
        String text = new String(body, StandardCharsets.UTF_8);
        long secretStarted = System.nanoTime();
        List<SecretDetector.Match> matches = detector.detect(text);
        DetectionRun secretRun = detector.run(text, matches, elapsedMicros(secretStarted));
        EdmContribution edm = edmContribution(text);
        if (matches.isEmpty() && edm.findings().isEmpty()) {
            return PolicyResult.clean(List.of(secretRun, edm.run()));
        }

        List<Finding> findings = new ArrayList<>(matches.size());
        List<SecretDetector.Match> maskMatches = new ArrayList<>();
        Set<String> blockingRules = new LinkedHashSet<>();
        Action effective = Action.FLAG;

        for (SecretDetector.Match m : matches) {
            Action action = actionFor(m.rule());
            // A match found inside a decoded blob has no safely-replaceable span in the
            // original body, so MASK collapses to FLAG (Rulepack Phase 3, like the
            // oversize/streamed paths). BLOCK still wins.
            if (m.decoded() && action == Action.MASK) {
                action = Action.FLAG;
            }
            findings.add(new Finding(SecretDetector.DETECTOR_ID, m.rule(), action));
            effective = mostSevere(effective, action);
            if (action == Action.BLOCK) {
                blockingRules.add(m.rule());
            } else if (action == Action.MASK) {
                maskMatches.add(m);
            }
        }
        findings.addAll(edm.findings());
        blockingRules.addAll(edm.blockingRules());
        effective = mostSevere(effective, edm.effective());

        if (effective == Action.BLOCK) {
            // Block wins: do not mask, stop the request.
            return new PolicyResult(findings, Action.BLOCK, Optional.empty(),
                    new ArrayList<>(blockingRules), edm.counts(), edm.complete(), edm.reason(),
                    List.of(secretRun, edm.run()));
        }
        if (effective == Action.MASK) {
            String masked = masker.mask(text, maskMatches);
            return new PolicyResult(findings, Action.MASK,
                    Optional.of(masked.getBytes(StandardCharsets.UTF_8)), List.of(), edm.counts(),
                    edm.complete(), edm.reason(), List.of(secretRun, edm.run()));
        }
        // FLAG only: record findings, let Egress proceed unchanged.
        return new PolicyResult(findings, Action.FLAG, Optional.empty(), List.of(), edm.counts(),
                edm.complete(), edm.reason(), List.of(secretRun, edm.run()));
    }

    /**
     * Evaluate a buffered <em>prefix</em> of an oversized body. The tail beyond the cap is
     * uninspected and a partial/streamed body cannot be safely rewritten, so a match may
     * only FLAG or BLOCK — a {@code MASK} rule is downgraded to {@link Action#FLAG} here.
     * "Block wins" still holds. This closes the gap where real Agent turns (routinely larger
     * than the cap) would otherwise egress a leading secret entirely uninspected.
     */
    public PolicyResult evaluatePrefix(byte[] prefix) {
        if (prefix == null || prefix.length == 0) {
            return PolicyResult.clean(List.of(emptySecretRun(), disabledEdmRun()));
        }
        String text = new String(prefix, StandardCharsets.UTF_8);
        return prefixResult(text, edmContribution(text));
    }

    /**
     * Evaluate one streamed chunk window (overlap included) of an oversize Turn. Same
     * FLAG/BLOCK-only semantics as {@link #evaluatePrefix}, but EDM matches accumulate
     * into {@code accumulator} so the distinct-match block threshold applies to the
     * whole Turn, not one window: a dump split across chunk boundaries
     * still blocks once the Turn's running total crosses the threshold.
     */
    public PolicyResult evaluateStreamChunk(byte[] window, ai.hamza.edm.EdmTurnAccumulator accumulator) {
        if (window == null || window.length == 0) {
            return PolicyResult.clean(List.of(emptySecretRun(), disabledEdmRun()));
        }
        String text = new String(window, StandardCharsets.UTF_8);
        EdmContribution edm = disabledEdmContribution();
        if (edmMatcher != null && edmMatcher.enabled() && accumulator != null) {
            long edmStarted = System.nanoTime();
            accumulator.add(edmMatcher.scanCounts(text));
            edm = edmFromCounts(accumulator.counts(), accumulator.complete(),
                    accumulator.exhaustionReason(), accumulator.typedRegistryIds(), text,
                    elapsedMicros(edmStarted));
        }
        return prefixResult(text, edm);
    }

    private PolicyResult prefixResult(String text, EdmContribution edm) {
        long secretStarted = System.nanoTime();
        List<SecretDetector.Match> matches = detector.detect(text);
        DetectionRun secretRun = detector.run(text, matches, elapsedMicros(secretStarted));
        if (matches.isEmpty() && edm.findings().isEmpty()) {
            return PolicyResult.clean(List.of(secretRun, edm.run()));
        }
        List<Finding> findings = new ArrayList<>(matches.size());
        Set<String> blockingRules = new LinkedHashSet<>();
        Action effective = Action.FLAG;
        for (SecretDetector.Match m : matches) {
            // Partial body: MASK cannot be applied safely, so it collapses to FLAG.
            Action action = actionFor(m.rule()) == Action.BLOCK ? Action.BLOCK : Action.FLAG;
            findings.add(new Finding(SecretDetector.DETECTOR_ID, m.rule(), action));
            effective = mostSevere(effective, action);
            if (action == Action.BLOCK) {
                blockingRules.add(m.rule());
            }
        }
        findings.addAll(edm.findings());
        blockingRules.addAll(edm.blockingRules());
        effective = mostSevere(effective, edm.effective());
        return effective == Action.BLOCK
                ? new PolicyResult(findings, Action.BLOCK, Optional.empty(),
                        new ArrayList<>(blockingRules), edm.counts(), edm.complete(), edm.reason(),
                        List.of(secretRun, edm.run()))
                : new PolicyResult(findings, Action.FLAG, Optional.empty(), List.of(), edm.counts(),
                        edm.complete(), edm.reason(), List.of(secretRun, edm.run()));
    }

    /**
     * Exact-Data-Match contribution. Rule name: {@code edm-<registry>}.
     * A registry's configured Action may escalate beyond FLAG only at
     * {@code edmBlockThreshold}+ DISTINCT matched values in this scan window — one
     * shared value is noise, thirty distinct values is the customer table. EDM has no
     * reliable spans, so MASK is clamped to FLAG; enforcement is BLOCK only.
     */
    private EdmContribution edmContribution(String text) {
        if (edmMatcher == null || !edmMatcher.enabled()) {
            return disabledEdmContribution();
        }
        long started = System.nanoTime();
        EdmCountScanResult scan = edmMatcher.scanCounts(text);
        return edmFromCounts(scan.counts(), scan.complete(), scan.exhaustionReason(),
                scan.typedRegistryIds(), text, elapsedMicros(started));
    }

    private EdmContribution edmFromCounts(Map<String, Integer> counts) {
        return edmFromCounts(counts, true, Optional.empty(), Set.of(), "", 0);
    }

    private EdmContribution edmFromCounts(Map<String, Integer> counts, boolean complete,
                                          Optional<EdmScanExhaustionReason> reason,
                                          Set<String> typedRegistryIds, String text,
                                          long durationMicros) {
        if (counts.isEmpty() && complete) {
            return new EdmContribution(List.of(), Set.of(), Action.FLAG, Map.of(), true,
                    Optional.empty(), completeEdmRun(text, List.of(), durationMicros));
        }
        List<Finding> findings = new ArrayList<>(counts.size() + (complete ? 0 : 1));
        Set<String> blockingRules = new LinkedHashSet<>();
        Action effective = Action.FLAG;
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            String rule = "edm-" + e.getKey();
            Action configured = actionFor(rule);
            int threshold = edmMatcher == null || !typedRegistryIds.contains(e.getKey())
                    ? edmBlockThreshold : edmMatcher.blockThreshold(e.getKey(), edmBlockThreshold);
            Action action = e.getValue() >= threshold && configured == Action.BLOCK
                    ? Action.BLOCK : Action.FLAG;
            findings.add(new Finding("edm", rule, action));
            effective = mostSevere(effective, action);
            if (action == Action.BLOCK) {
                blockingRules.add(rule);
            }
        }
        if (!complete) {
            findings.add(new Finding("edm", "scan-incomplete", Action.FLAG));
        }
        List<DetectionFinding> transientFindings = findings.stream()
                .map(finding -> new DetectionFinding(finding.rule(), finding.action(),
                        null, null, null, null, false))
                .toList();
        long bytes = text == null ? 0 : text.getBytes(StandardCharsets.UTF_8).length;
        DetectionRun run = new DetectionRun("edm", "edm-v1",
                complete ? DetectionStatus.COMPLETE : DetectionStatus.INCOMPLETE,
                complete ? Optional.empty() : Optional.of(mapReason(reason)),
                1, complete ? 1 : 0, bytes, complete ? bytes : 0,
                durationMicros, transientFindings);
        return new EdmContribution(findings, blockingRules, effective, counts,
                complete, reason == null ? Optional.empty() : reason, run);
    }

    private record EdmContribution(List<Finding> findings, Set<String> blockingRules,
                                   Action effective, Map<String, Integer> counts,
                                   boolean complete,
                                   Optional<EdmScanExhaustionReason> reason,
                                   DetectionRun run) {
    }

    private static DetectionReason mapReason(Optional<EdmScanExhaustionReason> reason) {
        if (reason == null || reason.isEmpty()) {
            return DetectionReason.OUTPUT_LIMIT;
        }
        return switch (reason.get()) {
            case CANDIDATE_LIMIT -> DetectionReason.OUTPUT_LIMIT;
        };
    }

    private static EdmContribution disabledEdmContribution() {
        return new EdmContribution(List.of(), Set.of(), Action.FLAG, Map.of(), true,
                Optional.empty(), disabledEdmRun());
    }

    private static DetectionRun disabledEdmRun() {
        return DetectionRun.skipped("edm", "edm-v1", DetectionReason.DISABLED);
    }

    private static DetectionRun emptySecretRun() {
        return new DetectionRun(SecretDetector.DETECTOR_ID, SecretDetector.DETECTOR_VERSION,
                DetectionStatus.COMPLETE, Optional.empty(), 1, 1, 0, 0, 0, List.of());
    }

    private static DetectionRun completeEdmRun(String text, List<DetectionFinding> findings,
                                               long durationMicros) {
        long bytes = text == null ? 0 : text.getBytes(StandardCharsets.UTF_8).length;
        return new DetectionRun("edm", "edm-v1", DetectionStatus.COMPLETE, Optional.empty(),
                1, 1, bytes, bytes, durationMicros, findings);
    }

    private static long elapsedMicros(long startedNanos) {
        return Math.max(0, (System.nanoTime() - startedNanos) / 1_000L);
    }

    /**
     * Oversized bodies cannot be masked reliably (only a prefix is buffered). The blanket
     * oversize Action is FLAG in observe/mask posture; a BLOCK posture or explicit oversize
     * BLOCK override stops every oversize Turn before Egress regardless of content. Secrets
     * found in the buffered prefix are handled separately by {@link #evaluatePrefix}.
     */
    public Action oversizeAction() {
        Action action = actionFor("oversize");
        return action == Action.BLOCK ? Action.BLOCK : Action.FLAG;
    }

    /** Bounded policy lookup used by the managed Mask pipeline for exact segment Findings. */
    public Action configuredAction(String rule) {
        return actionFor(rule);
    }

    private Action actionFor(String rule) {
        return ruleActions.getOrDefault(rule, posture);
    }

    private static Action mostSevere(Action a, Action b) {
        return severity(b) > severity(a) ? b : a;
    }

    private static int severity(Action a) {
        return switch (a) {
            case FLAG -> 0;
            case MASK -> 1;
            case BLOCK -> 2;
        };
    }
}
