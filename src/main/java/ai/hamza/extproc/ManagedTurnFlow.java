package ai.hamza.extproc;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.adapter.RequestView;
import ai.hamza.continuation.ByteCount;
import ai.hamza.continuation.ManagedMetadataDecision;
import ai.hamza.continuation.ManagedMetadataVerifier;
import ai.hamza.continuation.QuarantineAdmission;
import ai.hamza.masking.MaskContinuationResult;
import ai.hamza.persistence.ContinuationEvidence;
import ai.hamza.policy.Action;
import ai.hamza.policy.DetectionStatus;
import ai.hamza.policy.Finding;
import ai.hamza.policy.PolicyResult;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;

import static ai.hamza.extproc.StructuredEventLogger.Event.MASK_APPLIED;
import static ai.hamza.extproc.StructuredEventLogger.Event.MASK_FAILED;
import static ai.hamza.extproc.StructuredEventLogger.Event.MASK_PLANNED;
import static ai.hamza.extproc.StructuredEventLogger.Event.RECORD_FAILED;
import static ai.hamza.extproc.StructuredEventLogger.Field.ACTION;
import static ai.hamza.extproc.StructuredEventLogger.Field.BYTES;
import static ai.hamza.extproc.StructuredEventLogger.Field.COUNT;
import static ai.hamza.extproc.StructuredEventLogger.Field.REASON;
import static ai.hamza.extproc.StructuredEventLogger.Field.TURN_ID;

/**
 * Managed-route admission and masking: verifies the managed metadata header, quarantines
 * the source body, applies the Mask Continuation, and re-inspects the derived body before
 * Egress. Every path that cannot prove a clean rewrite fails closed.
 */
final class ManagedTurnFlow {

    private static final StructuredEventLogger events =
            StructuredEventLogger.forClass(ManagedTurnFlow.class);

    private final TurnPipeline pipeline;
    private final ManagedContinuationRuntime managedRuntime;
    private final TurnRecordFinalizer finalizer;

    ManagedTurnFlow(TurnPipeline pipeline, ManagedContinuationRuntime managedRuntime,
                    TurnRecordFinalizer finalizer) {
        this.pipeline = pipeline;
        this.managedRuntime = managedRuntime;
        this.finalizer = finalizer;
    }

    TurnPipeline.Decision onManagedRequestHeaders(TurnState state,
                                                  TurnPipeline.RequestHeaders headerView,
                                                  boolean requestEndOfStream) {
        if (!managedRuntime.enabled()) {
            return blockManagedHeaders(state, TurnState.CONTINUATION_INELIGIBLE_RULE);
        }
        ManagedMetadataDecision decision = managedRuntime.metadataVerifier()
                .verify(headerView.managedHeaders());
        ManagedMetadataDecision.Verified verified = switch (decision) {
            case ManagedMetadataDecision.Verified value -> value;
            case ManagedMetadataDecision.Invalid ignored -> null;
            case ManagedMetadataDecision.Absent ignored -> null;
            case null -> null;
        };
        if (verified == null) {
            return blockManagedHeaders(state, TurnState.MANAGED_METADATA_RULE);
        }
        if (state.adapter() == null
                || !verified.profile().provider().equals(state.adapter().provider())
                || !verified.profile().agent().equals(state.agent())) {
            return blockManagedHeaders(state, TurnState.MANAGED_METADATA_RULE);
        }

        Map<String, String> headers = headerView.routingHeaders();
        String contentEncoding = headers.get("content-encoding");
        if (contentEncoding != null && !contentEncoding.isBlank()
                && !"identity".equalsIgnoreCase(contentEncoding.trim())) {
            return blockManagedHeaders(state, TurnState.OPAQUE_CONTENT_RULE);
        }
        if (headerView.duplicated("content-length")
                || headerView.duplicated("transfer-encoding")) {
            return blockManagedHeaders(state, TurnState.MANAGED_QUARANTINE_RULE);
        }
        String transferEncoding = headers.get("transfer-encoding");
        if (transferEncoding != null && !transferEncoding.isBlank()
                && !"chunked".equalsIgnoreCase(transferEncoding.trim())) {
            return blockManagedHeaders(state, TurnState.MANAGED_QUARANTINE_RULE);
        }
        if (transferEncoding != null && headers.containsKey("content-length")) {
            return blockManagedHeaders(state, TurnState.MANAGED_QUARANTINE_RULE);
        }

        Optional<Long> contentLength = strictContentLength(headers.get("content-length"));
        if (headers.containsKey("content-length") && contentLength.isEmpty()) {
            return blockManagedHeaders(state, TurnState.MANAGED_QUARANTINE_RULE);
        }
        if (contentLength.isPresent()) {
            long bytes = contentLength.get();
            state.setRequestContentLength(bytes);
            if (bytes > managedRuntime.maxBodyBytes()) {
                return blockManagedHeaders(state, TurnState.MANAGED_QUARANTINE_RULE);
            }
        }
        if (requestEndOfStream) {
            // A signed GET/HEAD has no body to quarantine or transform. Its complete
            // body scan is the empty input, so remove managed metadata and account it
            // as a normal zero-byte Provider Turn. Waiting for a REQUEST_BODY message
            // that Envoy will never send would misclassify real Egress as incomplete.
            state.setRequestByteCounts(0L, 0L, 0L);
            state.beginManagedPassThrough(verified);
            return TurnPipeline.Continue.mode(TurnPipeline.BodyMode.NONE,
                    new TreeSet<>(ManagedMetadataVerifier.internalHeaderNames()));
        }
        QuarantineAdmission admission = contentLength.isPresent()
                ? managedRuntime.quarantineBudget().tryReserve(new ByteCount(contentLength.get()))
                : managedRuntime.quarantineBudget().tryReserveUnknownLength();
        QuarantineAdmission.Reserved reserved = switch (admission) {
            case QuarantineAdmission.Reserved value -> value;
            case QuarantineAdmission.Denied ignored -> null;
            case null -> null;
        };
        if (reserved == null) {
            return blockManagedHeaders(state, TurnState.MANAGED_QUARANTINE_RULE);
        }
        state.beginManaged(verified, reserved.reservation());
        return TurnPipeline.Continue.mode(TurnPipeline.BodyMode.BUFFERED,
                new TreeSet<>(ManagedMetadataVerifier.internalHeaderNames()));
    }

    private TurnPipeline.Decision blockManagedHeaders(TurnState state, String rule) {
        state.mergeDetectorEvidence(pipeline.upstreamBlockEvidence(0L));
        Finding finding = new Finding(rule, Action.BLOCK);
        state.setPolicy(List.of(finding), Action.BLOCK);
        state.setRequestByteCounts(0L, 0L, 0L);
        PolicyResult policy = new PolicyResult(List.of(finding), Action.BLOCK,
                Optional.empty(), List.of(rule));
        finalizer.recordBlockedTurn(state, policy);
        return finalizer.emitBlock(state, List.of(rule));
    }

    TurnPipeline.Decision onManagedRequestBody(TurnState state, byte[] requestBody,
                                               boolean endOfStream) {
        byte[] sourceBody = requestBody == null ? new byte[0] : requestBody.clone();
        pipeline.recordDuration(TurnPipeline.Phase.QUARANTINE, state.quarantineDuration());
        if (!endOfStream) {
            return blockManagedBody(state, sourceBody.length, null,
                    TurnState.SCAN_INCOMPLETE_RULE, "source-scan-incomplete");
        }
        Long declared = state.requestContentLength();
        if (!state.acceptManagedBody(sourceBody.length)
                || (declared != null && declared != sourceBody.length)) {
            return blockManagedBody(state, sourceBody.length, null,
                    TurnState.MANAGED_QUARANTINE_RULE, "quarantine-bound");
        }

        RequestView requestView = state.adapter().parseRequest(sourceBody);
        state.setRequest(requestView);
        if (requestView.malformed()
                || !state.managedMetadata().profile().model()
                .equals(requestView.requestedModel())) {
            return blockManagedBody(state, sourceBody.length, null,
                    TurnState.WIRE_DRIFT_RULE, "wire-drift");
        }

        state.setRequestByteCounts((long) sourceBody.length, (long) sourceBody.length, 0L);

        // No duplicate suppression here: a real CLI Agent fires identical bodies
        // more than once by design (parallel side calls, transport retries), and a
        // 403 on the repeat aborts the whole session. Masking is idempotent — the
        // Mask Scope renders the same Placeholders — so a repeat egress is
        // byte-identical and releases nothing new.
        String scopeId = state.managedMetadata().recoveryId().value();
        long maskScanStarted = System.nanoTime();
        MaskContinuationResult mask = managedRuntime.maskContinuation()
                .apply(scopeId, state.adapter(), sourceBody);
        pipeline.recordDuration(TurnPipeline.Phase.SOURCE_SCAN,
                Duration.ofNanos(System.nanoTime() - maskScanStarted));
        switch (mask) {
        case MaskContinuationResult.Masked masked -> {
            byte[] derivedBody = masked.derivedBody();
            // The segment scan cannot see JSON the Adapter does not collect (a tool
            // description, a field name), so the complete DERIVED body is re-inspected
            // before Egress. Any remaining Finding or Registry hit fails closed.
            long finalScanStarted = System.nanoTime();
            PolicyResult finalPolicy = pipeline.inspect(derivedBody);
            pipeline.recordDuration(TurnPipeline.Phase.FINAL_SCAN,
                    Duration.ofNanos(System.nanoTime() - finalScanStarted));
            if (hasEnforcingFinalScanResidue(finalPolicy)) {
                recordContinuationStatus(TurnPipeline.Status.FAILED_CLOSED);
                events.warn(MASK_FAILED, Map.of(TURN_ID, state.turnId(),
                        REASON, "final-scan-dirty"));
                managedRuntime.maskContinuation().closeScope(scopeId);
                List<Finding> detected = masked.sourceRuns().stream()
                        .flatMap(run -> run.durableFindings().stream()).toList();
                state.mergeDetectorEvidence(masked.sourceRuns().stream()
                        .map(ai.hamza.policy.DetectionRun::evidence).toList());
                PolicyResult dirtyPolicy = new PolicyResult(detected, Action.BLOCK,
                        Optional.empty(), List.of(TurnState.CONTINUATION_FAILED_RULE));
                return blockManagedBody(state, sourceBody.length, dirtyPolicy,
                        TurnState.CONTINUATION_FAILED_RULE, "mask-final-scan-dirty");
            }
            recordContinuationStatus(TurnPipeline.Status.ELIGIBLE);
            events.info(MASK_PLANNED, Map.of(TURN_ID, state.turnId(),
                    COUNT, masked.maskedValueCount(), ACTION, Action.MASK));
            state.mergeDetectorEvidence(masked.sourceRuns().stream()
                    .map(ai.hamza.policy.DetectionRun::evidence).toList());
            state.mergeEdmCounts(masked.edmDistinctCounts());
            state.setPolicy(masked.sourceFindings(), Action.MASK);
            try {
                appendManagedMaskSource(state, masked.sourceFindings(),
                        masked.edmDistinctCounts(), sourceBody.length,
                        masked.maskedValueCount());
            } catch (RuntimeException e) {
                events.warn(RECORD_FAILED, Map.of(TURN_ID, state.turnId(),
                        REASON, e.getClass().getSimpleName()));
                events.warn(MASK_FAILED, Map.of(TURN_ID, state.turnId(),
                        REASON, "source-record"));
                managedRuntime.maskContinuation().closeScope(scopeId);
                state.releaseQuarantine();
                state.markFinalizedOnce();
                return finalizer.emitBlock(state, List.of(TurnState.RECORD_COMMIT_RULE));
            }
            state.promoteToDerived();
            state.setRequest(state.adapter().parseRequest(derivedBody));
            state.setPolicy(List.of(), Action.FLAG);
            state.mergeDetectorEvidence(masked.finalRuns().stream()
                    .map(ai.hamza.policy.DetectionRun::evidence).toList());
            state.mergeDetectorEvidence(finalPolicy.detectorEvidence());
            state.setRequestByteCounts((long) derivedBody.length,
                    (long) derivedBody.length, (long) derivedBody.length);
            state.releaseQuarantine();
            events.info(MASK_APPLIED, Map.of(TURN_ID, state.turnId(),
                    BYTES, derivedBody.length, COUNT, masked.maskedValueCount()));
            return TurnPipeline.Continue.replace(derivedBody, true);
        }
        case MaskContinuationResult.Failed failed -> {
            recordContinuationStatus(TurnPipeline.Status.FAILED_CLOSED);
            events.warn(MASK_FAILED, Map.of(TURN_ID, state.turnId(),
                    REASON, reasonCode(failed.reason())));
            state.mergeDetectorEvidence(failed.sourceRuns().stream()
                    .map(ai.hamza.policy.DetectionRun::evidence).toList());
            List<Finding> detected = failed.sourceRuns().stream()
                    .flatMap(run -> run.durableFindings().stream()).toList();
            PolicyResult failedPolicy = new PolicyResult(detected, Action.BLOCK,
                    Optional.empty(), List.of(TurnState.CONTINUATION_FAILED_RULE));
            return blockManagedBody(state, sourceBody.length, failedPolicy,
                    TurnState.CONTINUATION_FAILED_RULE,
                    "mask-" + reasonCode(failed.reason()));
        }
        case MaskContinuationResult.NotRequired ignored -> { }
        case null -> { }
        }

        // NotRequired: every detector ran to completion and found nothing to mask.
        long sourceScanStarted = System.nanoTime();
        PolicyResult sourcePolicy = pipeline.inspect(sourceBody);
        state.mergeDetectorEvidence(sourcePolicy.detectorEvidence());
        pipeline.recordDuration(TurnPipeline.Phase.SOURCE_SCAN,
                Duration.ofNanos(System.nanoTime() - sourceScanStarted));
        state.mergeEdmCounts(sourcePolicy.edmDistinctCounts());

        // A managed Agent must be able to take its first clean Turn so it can ask
        // to read the local fixture. The fully quarantined body has a complete EDM
        // scan, no match, and no Finding. Drop managed state before Egress so the
        // response becomes an ordinary content-free STANDARD Record.
        if (sourcePolicy.edmScanComplete()
                && sourcePolicy.edmDistinctCounts().isEmpty()
                && sourcePolicy.findings().isEmpty()
                && sourcePolicy.effectiveAction() == Action.FLAG) {
            state.setPolicy(List.of(), Action.FLAG);
            state.setRequestBytesEgressed((long) sourceBody.length);
            state.releaseQuarantine();
            state.promoteToManagedPassThrough();
            return TurnPipeline.Continue.unchanged();
        }

        // Findings without a maskable exact span (a FLAG-only rule, an incomplete
        // standard scan): the managed route never forwards a found raw value and
        // never rewrites without proof, so the Turn fails closed.
        recordContinuationStatus(TurnPipeline.Status.REJECTED);
        return blockManagedBody(state, sourceBody.length, sourcePolicy,
                TurnState.CONTINUATION_INELIGIBLE_RULE, "unmaskable-findings");
    }

    private TurnPipeline.Decision blockManagedBody(TurnState state, int sourceBytes,
                                                   PolicyResult sourcePolicy, String rule,
                                                   String reasonCode) {
        if (sourcePolicy == null) {
            state.mergeDetectorEvidence(pipeline.upstreamBlockEvidence(sourceBytes));
        }
        List<Finding> existing = sourcePolicy == null ? List.of() : sourcePolicy.findings();
        List<Finding> findings = withBlockingFinding(existing, rule);
        Map<String, Integer> edmCounts = sourcePolicy == null
                ? Map.of() : sourcePolicy.edmDistinctCounts();
        state.mergeEdmCounts(edmCounts);
        state.setRequestByteCounts((long) sourceBytes, (long) sourceBytes, 0L);
        state.setPolicy(findings, Action.BLOCK);
        try {
            appendManagedSource(state, findings, edmCounts, sourceBytes, reasonCode);
        } catch (RuntimeException e) {
            events.warn(RECORD_FAILED, Map.of(TURN_ID, state.turnId(),
                    REASON, e.getClass().getSimpleName()));
        } finally {
            state.releaseQuarantine();
        }
        state.markFinalizedOnce();
        return finalizer.emitBlock(state, List.of(rule));
    }

    private void appendManagedSource(TurnState state, List<Finding> findings,
                                     Map<String, Integer> edmCounts, long sourceBytes,
                                     String reasonCode) {
        var metadata = state.managedMetadata();
        String provider = state.adapter() == null ? metadata.profile().provider()
                : state.adapter().provider();
        String requestedModel = state.request() == null ? metadata.profile().model()
                : state.request().requestedModel();
        NormalizedTurn source = NormalizedTurn.blocked(
                state.sourceTurnId(), state.requestId(), state.sessionId(), state.agent(),
                provider, requestedModel, findings, state.elapsedMs(), sourceBytes,
                sourceBytes, 0L, edmCounts);
        ContinuationEvidence evidence = ContinuationEvidence.source(
                metadata.recoveryId().value(), metadata.profile().recipeId(),
                metadata.profile().recipeVersion(), metadata.profile().id(),
                metadata.profile().version(),
                metadata.profile().shape().name().toLowerCase(Locale.ROOT).replace('_', '-'),
                reasonCode, sourceBytes);
        pipeline.recordSource(source, evidence, state.detectorEvidence(), sourceBytes);
    }

    private void appendManagedMaskSource(TurnState state, List<Finding> findings,
                                         Map<String, Integer> edmCounts, long sourceBytes,
                                         int maskedValueCount) {
        var metadata = state.managedMetadata();
        String provider = state.adapter().provider();
        String requestedModel = state.request().requestedModel();
        NormalizedTurn source = NormalizedTurn.maskedSource(
                state.sourceTurnId(), state.requestId(), state.sessionId(), state.agent(),
                provider, requestedModel, findings, state.elapsedMs(), sourceBytes, edmCounts);
        ContinuationEvidence evidence = ContinuationEvidence.maskedSource(
                metadata.recoveryId().value(), metadata.profile().recipeId(),
                metadata.profile().recipeVersion(), metadata.profile().id(),
                metadata.profile().version(),
                metadata.profile().shape().name().toLowerCase(Locale.ROOT).replace('_', '-'),
                "masked-secret-edm", sourceBytes, maskedValueCount);
        pipeline.recordSource(source, evidence, state.detectorEvidence(), sourceBytes);
    }

    private static List<Finding> withBlockingFinding(List<Finding> existing, String rule) {
        List<Finding> findings = new ArrayList<>(existing == null ? List.of() : existing);
        findings.removeIf(finding -> finding.rule().equals(rule));
        findings.add(new Finding(rule, Action.BLOCK));
        return List.copyOf(findings);
    }

    private static String reasonCode(Enum<?> reason) {
        return reason.name().toLowerCase(Locale.ROOT).replace('_', '-');
    }

    private static boolean hasEnforcingFinalScanResidue(PolicyResult finalPolicy) {
        return !finalPolicy.edmScanComplete()
                || !finalPolicy.edmDistinctCounts().isEmpty()
                || finalPolicy.findings().stream().anyMatch(finding ->
                        finding.action() != Action.FLAG)
                || finalPolicy.detectionRuns().stream().anyMatch(run ->
                        run.status() == DetectionStatus.INCOMPLETE
                                || run.status() == DetectionStatus.UNAVAILABLE);
    }

    private static Optional<Long> strictContentLength(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String trimmed = value.trim();
        if (!trimmed.matches("0|[1-9][0-9]{0,18}")) {
            return Optional.empty();
        }
        try {
            long parsed = Long.parseLong(trimmed);
            return parsed < 0 ? Optional.empty() : Optional.of(parsed);
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    private void recordContinuationStatus(TurnPipeline.Status status) {
        pipeline.recordStatus(status);
    }

    void cancelManaged(TurnState state) {
        if (!state.isManaged()) {
            return;
        }
        state.releaseQuarantine();
        // Envoy can close the ext_proc stream with onError after the complete
        // Provider response was already normalized and durably appended. That is
        // transport teardown, not cancellation of the managed workflow. Only an
        // unfinished Turn is allowed to erase its volatile Mask Scope.
        if (state.isFinalized()) {
            return;
        }
        managedRuntime.maskContinuation().closeScope(
                state.managedMetadata().recoveryId().value());
        if (!state.isDerived()) {
            recordManagedIncomplete(state);
        }
    }

    void recordManagedIncomplete(TurnState state) {
        if (state.isFinalized()) {
            return;
        }
        long received = state.requestBytesReceived() == null
                ? 0L : state.requestBytesReceived();
        blockManagedBody(state, Math.toIntExact(received), null,
                TurnState.SCAN_INCOMPLETE_RULE, "source-scan-incomplete");
    }
}
