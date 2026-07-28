package ai.hamza.extproc;

import ai.hamza.adapter.ProviderAdapter;
import ai.hamza.adapter.RequestView;
import ai.hamza.config.HamzaProperties;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import ai.hamza.policy.PolicyResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static ai.hamza.extproc.StructuredEventLogger.Event.MASK_APPLIED;
import static ai.hamza.extproc.StructuredEventLogger.Event.TRANSPORT_ERROR;
import static ai.hamza.extproc.StructuredEventLogger.Event.TRANSPORT_REQUEST;
import static ai.hamza.extproc.StructuredEventLogger.Event.TRANSPORT_RESPONSE;
import static ai.hamza.extproc.StructuredEventLogger.Field.ACTION;
import static ai.hamza.extproc.StructuredEventLogger.Field.AGENT;
import static ai.hamza.extproc.StructuredEventLogger.Field.BYTES;
import static ai.hamza.extproc.StructuredEventLogger.Field.COUNT;
import static ai.hamza.extproc.StructuredEventLogger.Field.END_OF_STREAM;
import static ai.hamza.extproc.StructuredEventLogger.Field.PROVIDER;
import static ai.hamza.extproc.StructuredEventLogger.Field.REASON;
import static ai.hamza.extproc.StructuredEventLogger.Field.STATUS;
import static ai.hamza.extproc.StructuredEventLogger.Field.TURN_ID;

/**
 * Plain-Java processing state for one translated transport stream. Provider
 * authentication is discarded by the transport projection before this session opens.
 *
 * <p>This class is the transport-callback orchestrator only: standard-route body
 * inspection happens here, while the managed route, the streamed-oversize route, and
 * Record finalization are delegated to {@link ManagedTurnFlow}, {@link
 * StreamedOversizeFlow}, and {@link TurnRecordFinalizer} respectively.
 */
final class DefaultTurnPipelineSession implements TurnPipeline.Session {

    private static final StructuredEventLogger events =
            StructuredEventLogger.forClass(DefaultTurnPipelineSession.class);

    private final List<ProviderAdapter> adapters;
    private final TurnPipeline pipeline;
    private final int maxBodyBytes;
    private final List<String> controlPlanePaths;
    private final boolean streamOversize;
    private final CoachSessionTracker coachSessions;
    private final ReEncodedContentDetector reEncoded;
    private final boolean coachEnabled;
    private final TurnState state = new TurnState();
    private final TurnRecordFinalizer finalizer;
    private final ManagedTurnFlow managedFlow;
    private final StreamedOversizeFlow streamedOversizeFlow;

    DefaultTurnPipelineSession(List<ProviderAdapter> adapters, TurnPipeline pipeline,
                               CoachSessionTracker coachSessions,
                               ReEncodedContentDetector reEncoded,
                               int maxBodyBytes, List<String> controlPlanePaths,
                               boolean streamOversize,
                               ManagedContinuationRuntime managedRuntime,
                               boolean coachEnabled) {
        this.adapters = adapters == null ? List.of() : List.copyOf(adapters);
        this.pipeline = java.util.Objects.requireNonNull(pipeline, "pipeline");
        this.coachSessions = coachSessions == null ? new CoachSessionTracker() : coachSessions;
        this.reEncoded = reEncoded == null ? new ReEncodedContentDetector() : reEncoded;
        this.maxBodyBytes = maxBodyBytes > 0 ? maxBodyBytes : HamzaProperties.DEFAULT_MAX_BODY_BYTES;
        this.controlPlanePaths = controlPlanePaths == null ? HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS
                : List.copyOf(controlPlanePaths);
        this.streamOversize = streamOversize;
        this.coachEnabled = coachEnabled;
        ManagedContinuationRuntime resolvedManagedRuntime = managedRuntime == null
                ? ManagedContinuationRuntime.disabled() : managedRuntime;
        this.finalizer = new TurnRecordFinalizer(pipeline, coachEnabled, this.coachSessions);
        this.managedFlow = new ManagedTurnFlow(pipeline, resolvedManagedRuntime, finalizer);
        this.streamedOversizeFlow = new StreamedOversizeFlow(pipeline, coachEnabled,
                this.coachSessions, this.reEncoded, finalizer);
    }

    @Override
    public void onTransportError(Throwable failure) {
        events.debug(TRANSPORT_ERROR, Map.of(TURN_ID, state.turnId(),
                REASON, failure.getClass().getSimpleName()));
        pipeline.recordStreamError();
        managedFlow.cancelManaged(state);
        finalizer.finalizeTurn(state);
    }

    @Override
    public void onTransportCompleted() {
        if (state.isManaged() && !state.isDerived()) {
            managedFlow.recordManagedIncomplete(state);
        }
        state.releaseQuarantine();
        finalizer.finalizeTurn(state);
    }

    @Override
    public void close() {
        state.close();
    }

    @Override
    public TurnPipeline.Decision onRequestHeaders(TurnPipeline.RequestHeaders headerView) {
        Map<String, String> map = headerView.routingHeaders();
        String path = map.getOrDefault(":path", "");
        state.setPath(path);
        state.setRequestId(map.get("x-request-id"));
        state.setContentEncoding(map.get("content-encoding"));
        state.setAgent(inferAgent(map));
        state.setSessionId(firstPresent(map, "session_id", "x-session-id", "conversation_id"));
        selectAdapter(path, map)
                .or(() -> isLocalGatePath(path)
                        ? Optional.empty()
                        : selectAdapterByProvider(headerView.routeProvider()))
                .ifPresent(state::selectAdapter);
        if (!headerView.managedHeaders().isEmpty()) {
            return managedFlow.onManagedRequestHeaders(state, headerView, headerView.endOfStream());
        }
        long contentLength = contentLength(map);
        state.setRequestContentLength(contentLength);
        if (isControlPlanePath(path)) {
            state.markOversize();
            state.setRequestByteCounts(contentLength, 0L, contentLength);
            events.info(TRANSPORT_REQUEST, Map.of(TURN_ID, state.turnId(),
                    PROVIDER, providerOf(state), AGENT, state.agent(), STATUS, "oversize"));
            return TurnPipeline.Continue.mode(TurnPipeline.BodyMode.NONE);
        }
        if (contentLength > maxBodyBytes) {
            Action oversizeAction = pipeline.oversizeAction();
            state.markOversize(oversizeAction);
            events.info(TRANSPORT_REQUEST, Map.of(TURN_ID, state.turnId(),
                    PROVIDER, providerOf(state), AGENT, state.agent(), STATUS, "oversize",
                    ACTION, oversizeAction));
            if (oversizeAction == Action.BLOCK) {
                state.setRequestByteCounts(0L, 0L, 0L);
                return finalizer.blockOversizeTurn(state, List.of(TurnState.OVERSIZE_RULE));
            }
            if (streamOversize) {
                // M7 spike: scan the WHOLE body chunk by chunk instead of prefix-only.
                state.markStreamedOversize();
                return TurnPipeline.Continue.mode(TurnPipeline.BodyMode.STREAMED);
            }
            // Still inspect the buffered prefix (bounded to the cap) rather than skip the body:
            // real Agent turns exceed the cap, and a leading secret must still be caught.
            return TurnPipeline.Continue.mode(TurnPipeline.BodyMode.BUFFERED_PARTIAL);
        }
        if (contentLength == 0) {
            state.setRequestByteCounts(0L, 0L, 0L);
        }
        events.info(TRANSPORT_REQUEST, Map.of(TURN_ID, state.turnId(),
                PROVIDER, providerOf(state), AGENT, state.agent()));
        if (contentLength > 0) {
            return TurnPipeline.Continue.mode(TurnPipeline.BodyMode.BUFFERED);
        }
        return TurnPipeline.Continue.unchanged();
    }

    @Override
    public TurnPipeline.Decision onRequestBody(byte[] requestBody, boolean endOfStream) {
        if (state.isManaged()) {
            return managedFlow.onManagedRequestBody(state, requestBody, endOfStream);
        }
        if (state.isStreamedOversize()) {
            return streamedOversizeFlow.onStreamedOversizeChunk(state, requestBody, endOfStream);
        }
        byte[] body = requestBody == null ? new byte[0] : requestBody.clone();
        if (state.isOversize() || isOverCapBody(body, endOfStream)) {
            Action oversizeAction = state.isOversize() ? state.action() : pipeline.oversizeAction();
            state.markOversize(oversizeAction);
            // Inspect the buffered prefix even though the tail is uninspected. A partial or
            // streamed body cannot be safely rewritten, so prefix findings only FLAG or BLOCK
            // (never MASK). Model is peeked from the prefix so real (oversize) Turns are
            // still attributed to a requested model.
            PolicyResult prefix = pipeline.inspectPrefix(body);
            state.mergeDetectorEvidence(prefix.detectorEvidence());
            state.mergeEdmCounts(prefix.edmDistinctCounts());
            if (state.adapter() != null) {
                state.adapter().peekModel(body).ifPresent(m -> state.setRequest(RequestView.ofModel(m)));
            }
            boolean block = oversizeAction == Action.BLOCK || prefix.isBlock();
            Long knownBodyBytes = knownBodyBytes(state, body.length, endOfStream);
            state.setRequestByteCounts(knownBodyBytes, (long) body.length, block ? 0L : knownBodyBytes);
            List<Finding> prefixFindings = new ArrayList<>(prefix.findings());
            if (BodyDecoder.isEncoded(state.contentEncoding())) {
                // An encoded oversize prefix cannot be decoded to completion: the scan ran
                // over wire bytes, not content. Say so instead of implying coverage.
                prefixFindings.add(new Finding(TurnState.OPAQUE_CONTENT_RULE, Action.FLAG));
            }
            state.setPolicy(prefixFindings, block ? Action.BLOCK : Action.FLAG);
            events.info(TRANSPORT_REQUEST, Map.of(TURN_ID, state.turnId(), BYTES, body.length,
                    END_OF_STREAM, endOfStream, COUNT, prefix.findings().size(),
                    ACTION, block ? Action.BLOCK : Action.FLAG, STATUS, "oversize"));
            if (block) {
                List<String> blockingRules = new ArrayList<>();
                if (oversizeAction == Action.BLOCK) {
                    blockingRules.add(TurnState.OVERSIZE_RULE);
                }
                blockingRules.addAll(prefix.blockingRules());
                return finalizer.blockOversizeTurn(state, blockingRules);
            }
            return TurnPipeline.Continue.unchanged();
        }
        // Decode-before-inspect: a compressed body fed raw to the detector is
        // fiction. An encoded body that cannot be decoded is opaque — a loud Finding,
        // never a silent pass. Decoded/opaque bodies may FLAG or BLOCK, never MASK
        // (spans refer to the decoded text, not the bytes on the wire).
        String encoding = state.contentEncoding();
        byte[] scanBytes = body;
        boolean decoded = false;
        boolean opaque = BodyDecoder.isOpaque(encoding);
        if (BodyDecoder.isSupported(encoding)) {
            var inflated = BodyDecoder.decode(body, encoding, maxDecodedBytes());
            if (inflated.isPresent()) {
                scanBytes = inflated.get();
                decoded = true;
            } else {
                opaque = true;
            }
        }

        if (state.adapter() != null) {
            state.setRequest(state.adapter().parseRequest(scanBytes));
        }
        // Wire-drift: the Adapter matched this path but cannot parse the body.
        // An Adapter that silently stops parsing degrades the Gate to a pass-through, so
        // the failure itself is a Finding. Opaque bodies are already reported as opaque.
        boolean wireDrift = state.adapter() != null && !opaque && scanBytes.length > 0
                && state.request().malformed();

        // Policy runs on the body ONLY — Authorization and other auth headers are never
        // passed here, never scanned, never a Finding (content-free invariant).
        PolicyResult policy = (decoded || opaque)
                ? pipeline.inspectPrefix(scanBytes)   // no safe span on the wire bytes
                : pipeline.inspect(scanBytes);
        state.mergeDetectorEvidence(policy.detectorEvidence());
        state.mergeEdmCounts(policy.edmDistinctCounts());
        List<Finding> findings = new ArrayList<>(policy.findings());
        if (wireDrift) {
            findings.add(new Finding(TurnState.WIRE_DRIFT_RULE, Action.FLAG));
        }
        if (opaque) {
            findings.add(new Finding(TurnState.OPAQUE_CONTENT_RULE, Action.FLAG));
        }
        // Evasion escalation: once a session has been coached, a later same-session
        // request that carries a newly re-encoded high-entropy blob is the base64/chunking
        // escape the coach forbade — hard Block, regardless of whether exact-match detection
        // (which encoding defeats) fired. Gated on Coach being enabled and a known session;
        // content-free (session id + a boolean only).
        boolean evaded = coachEnabled && coachSessions.wasCoached(state.sessionId())
                && reEncoded.looksReEncoded(scanBytes);
        if (evaded) {
            findings.add(new Finding(TurnState.EVASION_RULE, Action.BLOCK));
        }
        Action effectiveAction = evaded ? Action.BLOCK : policy.effectiveAction();
        state.setPolicy(findings, effectiveAction);
        state.setRequestByteCounts((long) body.length, (long) scanBytes.length,
                effectiveAction == Action.BLOCK ? 0L : (long) body.length);
        events.info(TRANSPORT_REQUEST, Map.of(TURN_ID, state.turnId(), BYTES, body.length,
                COUNT, findings.size(), ACTION, effectiveAction));

        if (evaded || policy.isBlock()) {
            List<String> blockingRules = new ArrayList<>(policy.blockingRules());
            if (evaded && !blockingRules.contains(TurnState.EVASION_RULE)) {
                blockingRules.add(TurnState.EVASION_RULE);
            }
            PolicyResult recorded = new PolicyResult(state.findings(), Action.BLOCK,
                    Optional.empty(), blockingRules);
            finalizer.recordBlockedTurn(state, recorded);
            return finalizer.emitBlock(state, blockingRules);
        }
        if (policy.isMask()) {
            byte[] masked = policy.maskedBody().orElseThrow();
            state.setRequestBytesEgressed((long) masked.length);
            events.info(MASK_APPLIED, Map.of(TURN_ID, state.turnId(), BYTES, masked.length));
            return TurnPipeline.Continue.replace(masked, false);
        }
        return TurnPipeline.Continue.unchanged();
    }

    /** Bound for inflating an encoded body before inspection (zip-bomb resistance). */
    private int maxDecodedBytes() {
        return Math.multiplyExact(maxBodyBytes, 8);
    }

    @Override
    public void onResponseHeaders(int status, boolean endOfStream) {
        state.setHttpStatus(status);
        events.info(TRANSPORT_RESPONSE, Map.of(TURN_ID, state.turnId(), STATUS, status));
        // HEAD and 204/304 responses have no response-body phase. Finalize at the
        // header end-of-stream marker so zero-body Provider requests still receive a
        // content-free Record and can reconcile against Envoy and the flow ledger.
        if (endOfStream) {
            finalizer.finalizeTurn(state);
        }
    }

    @Override
    public void onResponseBody(byte[] responseBody, boolean endOfStream) {
        byte[] body = responseBody == null ? new byte[0] : responseBody.clone();
        state.appendResponseBody(body);
        events.info(TRANSPORT_RESPONSE, Map.of(TURN_ID, state.turnId(),
                BYTES, body.length, END_OF_STREAM, endOfStream));
        if (endOfStream) {
            finalizer.finalizeTurn(state);
        }
    }

    private Optional<ProviderAdapter> selectAdapter(String path, Map<String, String> headers) {
        return adapters.stream().filter(a -> a.matches(path, headers)).findFirst();
    }

    private Optional<ProviderAdapter> selectAdapterByProvider(String provider) {
        if (provider == null || provider.isBlank()) {
            return Optional.empty();
        }
        return adapters.stream().filter(a -> a.provider().equals(provider)).findFirst();
    }

    private static String providerOf(TurnState state) {
        return state.adapter() == null ? "none" : state.adapter().provider();
    }

    private boolean isControlPlanePath(String path) {
        if (path == null || path.isBlank()) {
            return false;
        }
        return controlPlanePaths.stream().anyMatch(path::startsWith);
    }

    private static boolean isLocalGatePath(String path) {
        return "/ready".equals(path);
    }

    private long contentLength(Map<String, String> headers) {
        return parseLong(headers.get("content-length"));
    }

    private boolean isOverCapBody(byte[] body, boolean endOfStream) {
        return (body != null && body.length > maxBodyBytes) || !endOfStream;
    }

    private static Long knownBodyBytes(TurnState state, int observedBytes, boolean endOfStream) {
        Long contentLength = state.requestContentLength();
        if (contentLength != null && contentLength >= observedBytes) {
            return contentLength;
        }
        return endOfStream ? (long) observedBytes : null;
    }

    /** Best-effort Agent inference from User-Agent; {@code unknown} when not derivable. */
    private static String inferAgent(Map<String, String> headers) {
        String ua = headers.getOrDefault("user-agent", "").toLowerCase();
        if (ua.contains("codex")) {
            return "codex";
        }
        if (ua.contains("claude")) {
            return "claude-code";
        }
        return "unknown";
    }

    private static String firstPresent(Map<String, String> headers, String... keys) {
        for (String k : keys) {
            String v = headers.get(k);
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    private static long parseLong(String s) {
        if (s == null || s.isBlank()) {
            return 0;
        }
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
