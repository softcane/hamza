package ai.hamza.masking;

import ai.hamza.adapter.ContentSegment;
import ai.hamza.edm.EdmMatch;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.edm.EdmScanResult;
import ai.hamza.policy.Action;
import ai.hamza.policy.DetectionFinding;
import ai.hamza.policy.DetectionReason;
import ai.hamza.policy.DetectionRun;
import ai.hamza.policy.DetectionStatus;
import ai.hamza.policy.Finding;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.SecretDetector;
import ai.hamza.presidio.PresidioDetector;
import ai.hamza.presidio.PresidioFinding;
import ai.hamza.presidio.PresidioProfile;
import ai.hamza.presidio.PresidioScan;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Runs every registered detector over the decoded Provider-visible text segments.
 * Secret and EDM are always registered; Presidio is registered only when the
 * M3-approved profile is configured, and then a managed Turn also requires its
 * complete run.
 */
public final class MaskDetectionService {

    private static final String EDM_VERSION = "edm-v1";

    private final SecretDetector secrets;
    private final EdmMatcher edm;
    private final PolicyEngine policy;
    private final PresidioDetector presidio;
    private final int maxBodyBytes;
    private final int maxSegments;

    public MaskDetectionService(SecretDetector secrets, EdmMatcher edm, PolicyEngine policy) {
        this(secrets, edm, policy, null);
    }

    public MaskDetectionService(SecretDetector secrets, EdmMatcher edm, PolicyEngine policy,
                                PresidioDetector presidio) {
        this(secrets, edm, policy, presidio, MaskContinuationService.DEFAULT_MAX_BODY_BYTES,
                MaskPlanner.DEFAULT_MAX_SEGMENTS);
    }

    public MaskDetectionService(SecretDetector secrets, EdmMatcher edm, PolicyEngine policy,
                                PresidioDetector presidio, int maxBodyBytes, int maxSegments) {
        this.secrets = java.util.Objects.requireNonNull(secrets, "secrets");
        this.edm = java.util.Objects.requireNonNull(edm, "edm");
        this.policy = java.util.Objects.requireNonNull(policy, "policy");
        this.presidio = presidio;
        if (maxBodyBytes <= 0 || maxSegments <= 0) {
            throw new IllegalArgumentException("mask bounds must be positive");
        }
        this.maxBodyBytes = maxBodyBytes;
        this.maxSegments = maxSegments;
    }

    public MaskDetection scan(List<ContentSegment> segments) {
        List<ContentSegment> safe = segments == null ? List.of() : List.copyOf(segments);
        long receivedBytes = safe.stream().mapToLong(segment ->
                segment.text().getBytes(StandardCharsets.UTF_8).length).sum();
        if (safe.isEmpty() || safe.size() > maxSegments
                || receivedBytes > maxBodyBytes) {
            return incomplete(safe.size(), receivedBytes);
        }

        long secretStarted = System.nanoTime();
        List<DetectionFinding> secretFindings = new ArrayList<>();
        List<MaskCandidate> candidates = new ArrayList<>();
        Set<String> blocking = new LinkedHashSet<>();
        boolean unreliable = false;
        for (ContentSegment segment : safe) {
            for (SecretDetector.Match match : secrets.detect(segment.text())) {
                Action action = policy.configuredAction(match.rule());
                boolean reliable = !match.decoded();
                Integer start = reliable
                        ? segment.text().codePointCount(0, match.start()) : null;
                Integer end = reliable
                        ? segment.text().codePointCount(0, match.end()) : null;
                secretFindings.add(new DetectionFinding(match.rule(), action,
                        reliable ? segment.id() : null, start, end, null, reliable));
                if (action == Action.BLOCK) {
                    blocking.add(match.rule());
                } else if (action == Action.MASK && reliable) {
                    candidates.add(new MaskCandidate("secret", match.rule(),
                            PlaceholderFamily.SECRET, segment.id(), start, end));
                } else if (action == Action.MASK) {
                    unreliable = true;
                }
            }
        }
        DetectionRun secretRun = new DetectionRun("secret", SecretDetector.DETECTOR_VERSION,
                DetectionStatus.COMPLETE, Optional.empty(), safe.size(), safe.size(),
                receivedBytes, receivedBytes, elapsedMicros(secretStarted), secretFindings);

        long edmStarted = System.nanoTime();
        EdmScanResult edmScan = edm.scanContinuation(safe);
        List<DetectionFinding> edmFindings = new ArrayList<>();
        for (EdmMatch match : edmScan.matches()) {
            String rule = "edm-" + match.registryId();
            ContentSegment segment = safe.stream()
                    .filter(value -> value.id().equals(match.contentSegmentId()))
                    .findFirst().orElseThrow();
            int start = segment.text().codePointCount(0, match.start());
            int end = segment.text().codePointCount(0, match.end());
            // A Registry hit always masks on the managed route (owner decision
            // 2026-07-16): the registered value is withheld behind a placeholder and
            // the Turn continues, whatever the rule's standard-route Action says. The
            // recorded Finding carries MASK because masking is what happened here.
            edmFindings.add(new DetectionFinding(rule, Action.MASK, match.contentSegmentId(),
                    start, end, null, true));
            candidates.add(new MaskCandidate("edm", rule, PlaceholderFamily.EMAIL,
                    match.contentSegmentId(), start, end));
        }
        DetectionRun edmRun = new DetectionRun("edm", EDM_VERSION,
                edmScan.complete() ? DetectionStatus.COMPLETE : DetectionStatus.INCOMPLETE,
                edmScan.complete() ? Optional.empty() : Optional.of(DetectionReason.OUTPUT_LIMIT),
                safe.size(), edmScan.complete() ? safe.size() : 0,
                receivedBytes, edmScan.complete() ? receivedBytes : 0,
                elapsedMicros(edmStarted), edmFindings);
        List<DetectionRun> runs = new ArrayList<>(List.of(secretRun, edmRun));
        boolean complete = edmScan.complete();
        if (presidio != null) {
            PresidioScan presidioScan = presidio.scan(safe);
            List<DetectionFinding> presidioFindings = new ArrayList<>();
            for (PresidioFinding finding : presidioScan.findings()) {
                String rule = PresidioProfile.rule(finding.entity());
                Action action = policy.configuredAction(rule);
                presidioFindings.add(new DetectionFinding(rule, action, finding.segmentId(),
                        finding.start(), finding.end(), finding.score(), true));
                if (action == Action.BLOCK) {
                    blocking.add(rule);
                } else if (action == Action.MASK) {
                    candidates.add(new MaskCandidate(PresidioDetector.DETECTOR_ID, rule,
                            presidio.profile().family(finding.entity()), finding.segmentId(),
                            finding.start(), finding.end()));
                }
            }
            runs.add(new DetectionRun(PresidioDetector.DETECTOR_ID,
                    presidio.profile().detectorVersion(), presidioScan.status(),
                    presidioScan.reason(), presidioScan.receivedSegments(),
                    presidioScan.inspectedSegments(), presidioScan.receivedBytes(),
                    presidioScan.inspectedBytes(), presidioScan.durationMicros(),
                    presidioFindings));
            complete = complete && presidioScan.complete();
        }
        List<DetectionRun> orderedRuns = List.copyOf(runs);
        List<Finding> findings = orderedRuns.stream()
                .flatMap(run -> run.durableFindings().stream()).toList();
        return new MaskDetection(orderedRuns, candidates, findings, List.copyOf(blocking),
                edmScan.distinctCounts(), complete, unreliable);
    }

    private MaskDetection incomplete(int segments, long bytes) {
        List<DetectionRun> runs = new ArrayList<>();
        runs.add(inputLimited("secret", SecretDetector.DETECTOR_VERSION, segments, bytes));
        runs.add(inputLimited("edm", EDM_VERSION, segments, bytes));
        if (presidio != null) {
            runs.add(inputLimited(PresidioDetector.DETECTOR_ID,
                    presidio.profile().detectorVersion(), segments, bytes));
        }
        return new MaskDetection(List.copyOf(runs), List.of(), List.of(), List.of(),
                java.util.Map.of(), false, false);
    }

    private static DetectionRun inputLimited(String detectorId, String version, int segments,
                                             long bytes) {
        return new DetectionRun(detectorId, version, DetectionStatus.INCOMPLETE,
                Optional.of(DetectionReason.INPUT_LIMIT), Math.max(0, segments), 0,
                Math.max(0, bytes), 0, 0, List.of());
    }

    private static long elapsedMicros(long started) {
        return Math.max(0, (System.nanoTime() - started) / 1_000L);
    }
}
