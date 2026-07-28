package ai.hamza.masking;

import ai.hamza.adapter.ContinuationExtraction;
import ai.hamza.adapter.ContinuationTransformation;
import ai.hamza.adapter.ProviderAdapter;
import ai.hamza.policy.Action;
import java.util.List;
import java.util.Objects;

/** Complete managed M2 flow: detect, plan stable Placeholders, rebuild, rescan. */
public final class MaskContinuationService {

    /**
     * Default managed body bound. This is a default, not a limit: the operator sets
     * the real bound via {@code hamza.continuation.mask.max-body-bytes}. An Agent
     * harness appends its whole history to every request, so a managed body grows
     * with the session; a bound that a real Turn cannot fit under Blocks every Turn.
     */
    public static final int DEFAULT_MAX_BODY_BYTES = 1_048_576;

    private final MaskDetectionService detection;
    private final MaskPlanner planner;
    private final MaskScopeStore scopes;
    private final int maxBodyBytes;

    public MaskContinuationService(MaskDetectionService detection, MaskPlanner planner,
                                   MaskScopeStore scopes) {
        this(detection, planner, scopes, DEFAULT_MAX_BODY_BYTES);
    }

    public MaskContinuationService(MaskDetectionService detection, MaskPlanner planner,
                                   MaskScopeStore scopes, int maxBodyBytes) {
        this.detection = Objects.requireNonNull(detection, "detection");
        this.planner = Objects.requireNonNull(planner, "planner");
        this.scopes = Objects.requireNonNull(scopes, "scopes");
        if (maxBodyBytes <= 0) {
            throw new IllegalArgumentException("maxBodyBytes must be positive");
        }
        this.maxBodyBytes = maxBodyBytes;
    }

    public int maxBodyBytes() {
        return maxBodyBytes;
    }

    public MaskContinuationResult apply(String scopeId, ProviderAdapter adapter,
                                        byte[] sourceBody) {
        Objects.requireNonNull(adapter, "adapter");
        byte[] body = sourceBody == null ? new byte[0] : sourceBody.clone();
        if (body.length == 0 || body.length > maxBodyBytes) {
            return failed(scopeId, MaskContinuationResult.Reason.BODY_LIMIT, List.of());
        }
        ContinuationExtraction extracted = adapter.extractContinuation(body);
        ContinuationExtraction.Valid valid = switch (extracted) {
            case ContinuationExtraction.Valid value -> value;
            case ContinuationExtraction.Malformed ignored -> null;
            case ContinuationExtraction.Unsupported ignored -> null;
            case null -> null;
        };
        if (valid == null) {
            return failed(scopeId, MaskContinuationResult.Reason.ADAPTER_EXTRACTION, List.of());
        }
        MaskDetection source = detection.scan(valid.view().segments());
        if (!source.complete()) {
            return failed(scopeId, MaskContinuationResult.Reason.DETECTION_INCOMPLETE,
                    source.runs());
        }
        if (!source.blockingRules().isEmpty()) {
            return failed(scopeId, MaskContinuationResult.Reason.BLOCKING_FINDING,
                    source.runs());
        }
        if (source.unreliableEnforcingFinding()) {
            return failed(scopeId, MaskContinuationResult.Reason.UNRELIABLE_SPAN,
                    source.runs());
        }
        if (source.candidates().isEmpty()) {
            return new MaskContinuationResult.NotRequired(source.runs());
        }

        MaskPlan plan;
        try {
            plan = planner.plan(scopeId, valid.view().segments(), source.candidates());
        } catch (RuntimeException e) {
            return failed(scopeId, MaskContinuationResult.Reason.PLAN_INVALID, source.runs());
        }
        ContinuationTransformation transformed = adapter.transformContinuation(
                valid.view(), plan.edits(), "");
        ContinuationTransformation.Success success = switch (transformed) {
            case ContinuationTransformation.Success value -> value;
            case ContinuationTransformation.Failure ignored -> null;
            case null -> null;
        };
        if (success == null) {
            return failed(scopeId, MaskContinuationResult.Reason.REBUILD_FAILED, source.runs());
        }
        byte[] derived = success.body();
        if (derived.length == 0 || derived.length > maxBodyBytes) {
            return failed(scopeId, MaskContinuationResult.Reason.BODY_LIMIT, source.runs());
        }
        ContinuationExtraction finalExtraction = adapter.extractContinuation(derived);
        ContinuationExtraction.Valid finalView = switch (finalExtraction) {
            case ContinuationExtraction.Valid value -> value;
            case ContinuationExtraction.Malformed ignored -> null;
            case ContinuationExtraction.Unsupported ignored -> null;
            case null -> null;
        };
        if (finalView == null) {
            return failed(scopeId, MaskContinuationResult.Reason.REBUILD_FAILED, source.runs());
        }
        MaskDetection finalScan = detection.scan(finalView.view().segments());
        if (hasEnforcingFinalScanResidue(finalScan)) {
            return failed(scopeId, MaskContinuationResult.Reason.FINAL_SCAN_DIRTY,
                    source.runs());
        }
        var maskedFindings = source.findings().stream()
                .filter(finding -> finding.action() == Action.MASK)
                .toList();
        return new MaskContinuationResult.Masked(derived, source.runs(), finalScan.runs(),
                maskedFindings, source.edmDistinctCounts(), plan.maskedValueCount());
    }

    private static boolean hasEnforcingFinalScanResidue(MaskDetection finalScan) {
        return !finalScan.complete()
                || !finalScan.edmDistinctCounts().isEmpty()
                || finalScan.findings().stream().anyMatch(finding ->
                        finding.action() != Action.FLAG);
    }

    public void closeScope(String scopeId) {
        scopes.close(scopeId);
    }

    private MaskContinuationResult.Failed failed(String scopeId,
                                                  MaskContinuationResult.Reason reason,
                                                  List<ai.hamza.policy.DetectionRun> runs) {
        scopes.close(scopeId);
        return new MaskContinuationResult.Failed(reason, runs);
    }
}
