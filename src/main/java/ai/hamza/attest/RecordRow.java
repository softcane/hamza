package ai.hamza.attest;

import ai.hamza.policy.Finding;
import ai.hamza.policy.DetectorRunEvidence;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * One content-free Record row as read back for attestation (chain verification and
 * report generation). Mirrors the {@code turns} table plus its child {@code findings},
 * and its chain metadata ({@code seq}, {@code prevHash}, {@code entryHash}).
 */
public record RecordRow(
        long seq, String turnId, String requestId, String sessionId, String agent, String provider,
        String requestedModel, String servedModel, String status,
        long inputTokens, long cachedInputTokens, long uncachedInputTokens,
        long outputTokens, long reasoningTokens, long totalTokens,
        int toolCalls, String action, long durationMs, String ts,
        String posture, String configFingerprint, String hashVersion, String prevHash, String entryHash,
        Long requestBytesReceived, Long requestBytesInspected, Long requestBytesEgressed,
        RecordHasher.ContinuationHashFields continuation,
        List<DetectorRunEvidence> detectorRuns,
        List<Finding> findings, Map<String, EdmEvent> edmEvents) {

    public RecordRow {
        continuation = continuation == null
                ? RecordHasher.ContinuationHashFields.none() : continuation;
        detectorRuns = detectorRuns == null ? List.of() : List.copyOf(detectorRuns);
        findings = findings == null ? List.of() : List.copyOf(findings);
        edmEvents = edmEvents == null ? Map.of() : Map.copyOf(edmEvents);
    }

    /** Backwards-compatible constructor for report/reconciliation callers. */
    public RecordRow(
            long seq, String turnId, String requestId, String sessionId, String agent,
            String provider, String requestedModel, String servedModel, String status,
            long inputTokens, long cachedInputTokens, long uncachedInputTokens,
            long outputTokens, long reasoningTokens, long totalTokens,
            int toolCalls, String action, long durationMs, String ts,
            String posture, String configFingerprint, String hashVersion, String prevHash,
            String entryHash, Long requestBytesReceived, Long requestBytesInspected,
            Long requestBytesEgressed, List<Finding> findings, Map<String, EdmEvent> edmEvents) {
        this(seq, turnId, requestId, sessionId, agent, provider, requestedModel, servedModel,
                status, inputTokens, cachedInputTokens, uncachedInputTokens, outputTokens,
                reasoningTokens, totalTokens, toolCalls, action, durationMs, ts, posture,
                configFingerprint, hashVersion, prevHash, entryHash, requestBytesReceived,
                requestBytesInspected, requestBytesEgressed,
                RecordHasher.ContinuationHashFields.none(), List.of(), findings, edmEvents);
    }

    /** Backwards-compatible constructor for callers that carry continuation fields. */
    public RecordRow(
            long seq, String turnId, String requestId, String sessionId, String agent,
            String provider, String requestedModel, String servedModel, String status,
            long inputTokens, long cachedInputTokens, long uncachedInputTokens,
            long outputTokens, long reasoningTokens, long totalTokens,
            int toolCalls, String action, long durationMs, String ts,
            String posture, String configFingerprint, String hashVersion, String prevHash,
            String entryHash, Long requestBytesReceived, Long requestBytesInspected,
            Long requestBytesEgressed, RecordHasher.ContinuationHashFields continuation,
            List<Finding> findings, Map<String, EdmEvent> edmEvents) {
        this(seq, turnId, requestId, sessionId, agent, provider, requestedModel, servedModel,
                status, inputTokens, cachedInputTokens, uncachedInputTokens, outputTokens,
                reasoningTokens, totalTokens, toolCalls, action, durationMs, ts, posture,
                configFingerprint, hashVersion, prevHash, entryHash, requestBytesReceived,
                requestBytesInspected, requestBytesEgressed, continuation, List.of(),
                findings, edmEvents);
    }

    public record EdmEvent(String registry, int distinctCount, String action) {
    }

    /** The content-free projection this row hashes to, for independent recomputation. */
    public RecordHasher.HashableTurn hashable() {
        List<String> keys = new ArrayList<>(findings.size());
        for (Finding f : findings) {
            keys.add(RecordHasher.CURRENT_RECORD_VERSION.equals(hashVersion)
                    ? RecordHasher.findingKey(f.detector(), f.rule(), f.action().name())
                    : RecordHasher.findingKey(f.rule(), f.action().name()));
        }
        List<String> runKeys = detectorRuns.stream()
                .map(run -> RecordHasher.detectorRunKey(run.detectorId(), run.detectorVersion(),
                        run.status().name(), run.reason().map(Enum::name).orElse(null),
                        run.receivedSegments(), run.inspectedSegments(), run.receivedBytes(),
                        run.inspectedBytes(), run.durationMicros(), run.findingCount()))
                .toList();
        List<String> eventKeys = new ArrayList<>(edmEvents.size());
        edmEvents.values().forEach(event -> eventKeys.add(RecordHasher.edmEventKey(
                event.registry(), event.distinctCount(), event.action())));
        return new RecordHasher.HashableTurn(
                hashVersion == null ? RecordHasher.LEGACY_RECORD_VERSION : hashVersion,
                turnId, requestId, sessionId, agent, provider, requestedModel, servedModel, status,
                inputTokens, cachedInputTokens, uncachedInputTokens, outputTokens,
                reasoningTokens, totalTokens, toolCalls, action, durationMs, ts,
                posture, configFingerprint, requestBytesReceived, requestBytesInspected,
                requestBytesEgressed, continuation, eventKeys, runKeys, keys);
    }
}
