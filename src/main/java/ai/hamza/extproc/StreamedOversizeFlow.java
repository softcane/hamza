package ai.hamza.extproc;

import ai.hamza.adapter.RequestView;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import ai.hamza.policy.PolicyResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static ai.hamza.extproc.StructuredEventLogger.Event.TRANSPORT_REQUEST;
import static ai.hamza.extproc.StructuredEventLogger.Field.BYTES;
import static ai.hamza.extproc.StructuredEventLogger.Field.COUNT;
import static ai.hamza.extproc.StructuredEventLogger.Field.DURATION_MICROS;
import static ai.hamza.extproc.StructuredEventLogger.Field.END_OF_STREAM;
import static ai.hamza.extproc.StructuredEventLogger.Field.STATUS;
import static ai.hamza.extproc.StructuredEventLogger.Field.TURN_ID;

/**
 * M7 spike: full-body inspection of an oversize Turn via {@code STREAMED} chunks.
 * Each chunk is scanned with the previous chunk's 4 KiB tail prepended, so a secret
 * spanning a chunk boundary still matches, while memory stays bounded (the streamed
 * body is never accumulated). A streamed match may FLAG or BLOCK, never MASK.
 *
 * <p>Honesty invariant: chunks already CONTINUE'd have already egressed. A mid-stream
 * BLOCK stops only the remainder, so the blocked Turn additionally records a
 * {@code partial-egress} Finding — "blocked, but a prefix left" is never reported as
 * "nothing left".
 */
final class StreamedOversizeFlow {

    /**
     * Overlap carried between streamed-chunk scans (M7 spike): a secret spanning a chunk
     * boundary is caught because each chunk is scanned with the previous chunk's tail
     * prepended. 4 KiB comfortably exceeds every detectable token shape.
     */
    static final int STREAM_OVERLAP_BYTES = 4096;

    private static final StructuredEventLogger events =
            StructuredEventLogger.forClass(StreamedOversizeFlow.class);

    private final TurnPipeline pipeline;
    private final boolean coachEnabled;
    private final CoachSessionTracker coachSessions;
    private final ReEncodedContentDetector reEncoded;
    private final TurnRecordFinalizer finalizer;

    StreamedOversizeFlow(TurnPipeline pipeline, boolean coachEnabled,
                         CoachSessionTracker coachSessions, ReEncodedContentDetector reEncoded,
                         TurnRecordFinalizer finalizer) {
        this.pipeline = pipeline;
        this.coachEnabled = coachEnabled;
        this.coachSessions = coachSessions;
        this.reEncoded = reEncoded;
        this.finalizer = finalizer;
    }

    TurnPipeline.Decision onStreamedOversizeChunk(TurnState state, byte[] requestBody,
                                                  boolean endOfStream) {
        byte[] chunk = requestBody == null ? new byte[0] : requestBody.clone();
        boolean firstChunk = state.streamedBodyBytes() == 0;
        long scanStart = System.nanoTime();
        byte[] window = state.nextStreamScanWindow(chunk, STREAM_OVERLAP_BYTES);
        PolicyResult result = pipeline.inspectStream(window, state.edmAccumulator());
        state.mergeDetectorEvidence(result.detectorEvidence());
        state.mergeEdmCounts(result.edmDistinctCounts());
        long scanMicros = (System.nanoTime() - scanStart) / 1_000L;
        state.accumulateStreamFindings(result.findings());
        state.setRequestByteCounts(state.streamedBodyBytes(), state.streamedBodyBytes(), null);
        if (firstChunk && state.adapter() != null) {
            state.adapter().peekModel(window).ifPresent(m -> state.setRequest(RequestView.ofModel(m)));
        }
        if (firstChunk && BodyDecoder.isEncoded(state.contentEncoding())) {
            // Streaming decode is not implemented yet: an encoded streamed body is scanned
            // as wire bytes only. Keep that visible as opaque-content, not a silent pass.
            state.accumulateStreamFindings(List.of(new Finding(TurnState.OPAQUE_CONTENT_RULE, Action.FLAG)));
        }
        // Evasion escalation on the streamed path too: a coached session that
        // re-encodes its blocked payload into a large (oversize) body would otherwise slip
        // past exact-match detection, which base64/chunking defeats. A re-encoded chunk in a
        // coached session is a hard Block.
        boolean evaded = coachEnabled && coachSessions.wasCoached(state.sessionId())
                && reEncoded.looksReEncoded(window);
        if (evaded) {
            state.accumulateStreamFindings(List.of(new Finding(TurnState.EVASION_RULE, Action.BLOCK)));
        }
        events.info(TRANSPORT_REQUEST, Map.of(TURN_ID, state.turnId(), BYTES, chunk.length,
                END_OF_STREAM, endOfStream, DURATION_MICROS, scanMicros,
                COUNT, result.findings().size(), STATUS, "streamed"));
        if (evaded || result.isBlock()) {
            List<Finding> findings = new ArrayList<>(state.streamFindings());
            // Envoy forwards a streamed chunk only after its CONTINUE, so the blocking
            // chunk itself is withheld; partial egress happened only if earlier chunks
            // were already forwarded (live-verified: block on chunk 1 leaks zero bytes).
            long priorBytes = state.streamedBodyBytes() - chunk.length;
            state.setRequestBytesEgressed(priorBytes);
            if (priorBytes > 0) {
                findings.add(new Finding(TurnState.PARTIAL_EGRESS_RULE, Action.BLOCK));
            }
            state.setPolicy(findings, Action.BLOCK);
            List<String> blockingRules = new ArrayList<>(result.blockingRules());
            if (evaded && !blockingRules.contains(TurnState.EVASION_RULE)) {
                blockingRules.add(TurnState.EVASION_RULE);
            }
            PolicyResult policy = new PolicyResult(state.findings(), Action.BLOCK,
                    Optional.empty(), blockingRules);
            finalizer.recordBlockedTurn(state, policy);
            return finalizer.emitBlock(state, blockingRules);
        }
        if (endOfStream) {
            state.setPolicy(state.streamFindings(), Action.FLAG);
            state.setRequestBytesEgressed(state.streamedBodyBytes());
        }
        return TurnPipeline.Continue.unchanged();
    }
}
