package ai.hamza.adapter;

import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The normalised, content-free account of a Turn that the Gate keeps (CONTEXT
 * glossary: <em>Record</em>). One {@code NormalizedTurn} == one Agent→Provider
 * exchange, normalised across all Providers by an {@link ProviderAdapter}.
 *
 * <p>Invariant: holds accounting + Findings (rule + action) only —
 * never raw prompts, code, or secret values.
 *
 * <p>Token math invariants: {@code cachedInputTokens <= inputTokens};
 * {@code reasoningTokens <= outputTokens}; {@code totalTokens == inputTokens +
 * outputTokens}; {@code uncachedInputTokens == inputTokens - cachedInputTokens}.
 */
public record NormalizedTurn(
        String turnId,
        String sessionId,
        String agent,
        String provider,
        String requestedModel,
        String servedModel,
        String status,
        long inputTokens,
        long cachedInputTokens,
        long uncachedInputTokens,
        long outputTokens,
        long reasoningTokens,
        long totalTokens,
        int toolCalls,
        List<Finding> findings,
        Action action,
        long durationMs,
        Instant timestamp,
        String requestId,
        Long requestBytesReceived,
        Long requestBytesInspected,
        Long requestBytesEgressed,
        Map<String, Integer> edmDistinctCounts) {

    public NormalizedTurn(String turnId, String sessionId, String agent, String provider,
                          String requestedModel, String servedModel, String status,
                          long inputTokens, long cachedInputTokens, long uncachedInputTokens,
                          long outputTokens, long reasoningTokens, long totalTokens,
                          int toolCalls, List<Finding> findings, Action action,
                          long durationMs, Instant timestamp) {
        this(turnId, sessionId, agent, provider, requestedModel, servedModel, status,
                inputTokens, cachedInputTokens, uncachedInputTokens, outputTokens,
                reasoningTokens, totalTokens, toolCalls, findings, action, durationMs,
                timestamp, null, null, null, null, Map.of());
    }

    public NormalizedTurn {
        findings = findings == null ? List.of() : List.copyOf(findings);
        edmDistinctCounts = edmDistinctCounts == null ? Map.of() : Map.copyOf(edmDistinctCounts);
    }

    /** True if a model fallback occurred — the Provider served a different model than requested. */
    public boolean isModelFallback() {
        return requestedModel != null && servedModel != null && !requestedModel.equals(servedModel);
    }

    /** Return a copy with the policy outcome (Findings + resolved Action) attached. */
    public NormalizedTurn withPolicy(List<Finding> findings, Action action) {
        return new NormalizedTurn(turnId, sessionId, agent, provider, requestedModel, servedModel,
                status, inputTokens, cachedInputTokens, uncachedInputTokens, outputTokens,
                reasoningTokens, totalTokens, toolCalls, findings, action, durationMs, timestamp,
                requestId, requestBytesReceived, requestBytesInspected, requestBytesEgressed,
                edmDistinctCounts);
    }

    /** Return a copy with a bounded, content-free lifecycle status. */
    public NormalizedTurn withStatus(String newStatus) {
        return new NormalizedTurn(turnId, sessionId, agent, provider, requestedModel, servedModel,
                newStatus, inputTokens, cachedInputTokens, uncachedInputTokens, outputTokens,
                reasoningTokens, totalTokens, toolCalls, findings, action, durationMs, timestamp,
                requestId, requestBytesReceived, requestBytesInspected, requestBytesEgressed,
                edmDistinctCounts);
    }

    /**
     * A Turn whose Egress was Blocked before it reached the Provider: no Provider
     * response, so token accounting is zero and {@code status} is {@code "blocked"}.
     */
    public static NormalizedTurn blocked(String turnId, String sessionId, String agent, String provider,
                                         String requestedModel, List<Finding> findings, long durationMs) {
        return blocked(turnId, null, sessionId, agent, provider, requestedModel, findings,
                durationMs, null, null, null, Map.of());
    }

    public static NormalizedTurn blocked(String turnId, String requestId, String sessionId,
                                         String agent, String provider, String requestedModel,
                                         List<Finding> findings, long durationMs,
                                         Long requestBytesReceived, Long requestBytesInspected,
                                         Long requestBytesEgressed,
                                         Map<String, Integer> edmDistinctCounts) {
        return new NormalizedTurn(turnId, sessionId, agent, provider, requestedModel, null, "blocked",
                0, 0, 0, 0, 0, 0, 0, findings, Action.BLOCK, durationMs, Instant.now(),
                requestId, requestBytesReceived, requestBytesInspected, requestBytesEgressed,
                edmDistinctCounts);
    }

    /** A complete SOURCE Turn withheld because its exact Findings were Masked. */
    public static NormalizedTurn maskedSource(
            String turnId, String requestId, String sessionId, String agent,
            String provider, String requestedModel, List<Finding> findings,
            long durationMs, long sourceBytes, Map<String, Integer> edmDistinctCounts) {
        return new NormalizedTurn(turnId, sessionId, agent, provider, requestedModel, null,
                "withheld", 0, 0, 0, 0, 0, 0, 0, findings, Action.MASK, durationMs,
                Instant.now(), requestId, sourceBytes, sourceBytes, 0L, edmDistinctCounts);
    }
}
