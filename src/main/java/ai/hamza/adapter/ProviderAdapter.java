package ai.hamza.adapter;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.util.Map;
import java.util.List;
import java.util.Optional;

/**
 * The per-Provider component that recognises one Provider's wire format and normalises
 * a Turn into the common model (CONTEXT glossary: <em>Adapter</em>). Adding an
 * Agent/Provider means writing one Adapter.
 *
 * <p>Implementations are stateless singletons: per-Turn state lives in the ext_proc
 * stream (a {@code TurnState}), and is handed back here as a {@link TurnDraft} to
 * finalise. {@code provider()} is authoritative (derived from the wire); the Agent is
 * best-effort and resolved elsewhere.
 */
public interface ProviderAdapter {

    /** Authoritative Provider name for the Record/metrics (e.g. {@code "openai"}). */
    String provider();

    /** Content-free Provider metadata used for egress policy artifacts and coverage. */
    ProviderSpec spec();

    /**
     * Is this request my wire format? Decided from the request path and headers
     * (lower-cased keys), never from the body.
     */
    boolean matches(String path, Map<String, String> headers);

    /** Extract accounting from the outbound request body (no raw content retained). */
    RequestView parseRequest(byte[] body);

    /**
     * Extract decoded text only from Provider-approved content fields. No request headers,
     * including Provider Authorization, enter this interface.
     */
    default ContinuationExtraction extractContinuation(byte[] body) {
        return new ContinuationExtraction.Unsupported(
                ContinuationFailureReason.UNSUPPORTED_CONTENT);
    }

    /**
     * Apply decoded text edits and one fixed directive to a view issued by this Adapter.
     * Implementations mutate parsed content values only and return a newly serialized body.
     */
    default ContinuationTransformation transformContinuation(
            ContinuationView view, List<ReplacementEdit> edits, String fixedDirective) {
        return new ContinuationTransformation.Failure(
                ContinuationFailureReason.UNSUPPORTED_CONTENT);
    }

    /** Parse the accumulated response and produce the content-free {@link NormalizedTurn}. */
    NormalizedTurn finalizeTurn(TurnDraft draft);

    /** Shared streaming factory for {@link #peekModel} (thread-safe for creating parsers). */
    JsonFactory PEEK_FACTORY = new JsonFactory();

    /**
     * Best-effort extraction of the top-level {@code "model"} from a possibly-truncated
     * request-body <em>prefix</em>. Used to attribute an oversize Turn whose full body was
     * never buffered ({@code parseRequest} needs the whole body and fails on a truncated
     * one). The streaming parse returns as soon as the top-level model string is seen, so a
     * cut-off tail does not matter; returns empty if the model is not within the prefix.
     * Both OpenAI Responses and Anthropic Messages carry {@code model} at the top level, so
     * this default serves every Provider; override only for a different wire shape.
     */
    default Optional<String> peekModel(byte[] prefix) {
        if (prefix == null || prefix.length == 0) {
            return Optional.empty();
        }
        try (JsonParser parser = PEEK_FACTORY.createParser(prefix)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return Optional.empty();
            }
            int depth = 1;
            JsonToken token;
            while (depth > 0 && (token = parser.nextToken()) != null) {
                if (token == JsonToken.START_OBJECT || token == JsonToken.START_ARRAY) {
                    depth++;
                } else if (token == JsonToken.END_OBJECT || token == JsonToken.END_ARRAY) {
                    depth--;
                } else if (token == JsonToken.FIELD_NAME && depth == 1 && "model".equals(parser.currentName())) {
                    if (parser.nextToken() == JsonToken.VALUE_STRING) {
                        String model = parser.getValueAsString();
                        return model == null || model.isBlank() ? Optional.empty() : Optional.of(model);
                    }
                }
            }
        } catch (Exception e) {
            // Truncated after the model, or not JSON: best-effort only, attribute nothing.
        }
        return Optional.empty();
    }
}
