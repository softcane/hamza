package ai.hamza.adapter;

/**
 * What an {@link ProviderAdapter} extracts from an outbound request body — accounting
 * only, no raw content kept on the Record. {@code instructionChars} / {@code inputChars}
 * are <em>lengths</em>, never the text itself (content-free invariant).
 */
public record RequestView(
        String requestedModel,
        int toolCount,
        int instructionChars,
        int inputChars,
        boolean malformed) {

    public RequestView(String requestedModel, int toolCount, int instructionChars, int inputChars) {
        this(requestedModel, toolCount, instructionChars, inputChars, false);
    }

    public static RequestView empty() {
        return new RequestView(null, 0, 0, 0);
    }

    /**
     * The Adapter matched this Turn's wire format but could not parse the body. Silent
     * pass-through on parse failure is how a Gate degrades to fiction — the caller must
     * surface this as a loud {@code wire-drift} Finding (AGENTS.md).
     */
    public static RequestView unparseable() {
        return new RequestView(null, 0, 0, 0, true);
    }

    /**
     * A view carrying only the requested model — used to attribute an oversize Turn whose
     * full body was never buffered, so only the model could be peeked from the prefix.
     */
    public static RequestView ofModel(String requestedModel) {
        return new RequestView(requestedModel, 0, 0, 0);
    }
}
