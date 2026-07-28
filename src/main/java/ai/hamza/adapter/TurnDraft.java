package ai.hamza.adapter;

/**
 * The per-stream inputs an {@link ProviderAdapter} needs to finalise a
 * {@link NormalizedTurn}: identity and accounting gathered across the Turn's phases,
 * plus the accumulated response body to parse.
 *
 * <p>The {@code responseBody} is transient working state held only for the duration of
 * the stream; it is parsed into accounting and then discarded — it never reaches the
 * durable Record (content-free invariant).
 */
public record TurnDraft(
        String turnId,
        String requestId,
        String sessionId,
        String agent,
        RequestView request,
        int httpStatus,
        byte[] responseBody,
        long durationMs,
        Long requestBytesReceived,
        Long requestBytesInspected,
        Long requestBytesEgressed,
        java.util.Map<String, Integer> edmDistinctCounts) {

    public TurnDraft(String turnId, String sessionId, String agent, RequestView request,
                     int httpStatus, byte[] responseBody, long durationMs) {
        this(turnId, null, sessionId, agent, request, httpStatus, responseBody, durationMs,
                null, null, null, java.util.Map.of());
    }

    public TurnDraft {
        edmDistinctCounts = edmDistinctCounts == null ? java.util.Map.of()
                : java.util.Map.copyOf(edmDistinctCounts);
    }
}
