package ai.hamza.adapter;

import ai.hamza.policy.Action;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Adapter for the Anthropic Messages wire format (Claude Code → {@code /v1/messages}).
 * Thin by design: its job is to prove the seam — a second Provider normalised through
 * the <em>same</em> policy / metrics / Record pipeline, "write one Adapter, not
 * a rewrite."
 *
 * <p>Anthropic streams {@code message_start} (carrying input usage), {@code content_block_*},
 * a terminal {@code message_delta} (carrying output usage + {@code stop_reason}), and
 * {@code message_stop}. Token accounting is normalised so the invariants hold:
 * {@code cached <= input} and {@code total = input + output}.
 */
@Component
public class AnthropicMessagesAdapter implements ProviderAdapter {

    private static final String PROVIDER = "anthropic";
    private static final ProviderSpec SPEC = new ProviderSpec(PROVIDER,
            List.of("api.anthropic.com"),
            List.of("/v1/messages"));
    private static final Set<String> MESSAGE_ROLES = Set.of("user", "assistant");
    private static final Set<String> ROOT_FIELDS = Set.of(
            "model", "max_tokens", "messages", "system", "tools", "tool_choice",
            "metadata", "stop_sequences", "stream", "temperature", "top_k", "top_p",
            "thinking", "service_tier", "output_config", "container",
            "context_management", "mcp_servers");
    private static final Set<String> MESSAGE_FIELDS = Set.of("role", "content");
    private static final Set<String> TEXT_BLOCK_FIELDS = Set.of(
            "type", "text", "cache_control", "citations");
    private static final Set<String> TOOL_USE_FIELDS = Set.of(
            "type", "id", "name", "input", "cache_control", "caller");
    private static final Set<String> TOOL_RESULT_FIELDS = Set.of(
            "type", "tool_use_id", "content", "is_error", "cache_control");
    private static final Set<String> THINKING_FIELDS = Set.of(
            "type", "thinking", "signature");
    private static final Set<String> REDACTED_THINKING_FIELDS = Set.of("type", "data");

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public String provider() {
        return PROVIDER;
    }

    @Override
    public ProviderSpec spec() {
        return SPEC;
    }

    @Override
    public boolean matches(String path, Map<String, String> headers) {
        return path != null && path.contains("/v1/messages");
    }

    @Override
    public RequestView parseRequest(byte[] body) {
        if (body == null || body.length == 0) {
            return RequestView.empty();
        }
        try {
            JsonNode root = mapper.readTree(body);
            String model = root.path("model").asText(null);
            int toolCount = root.path("tools").isArray() ? root.path("tools").size() : 0;
            int systemChars = lengthOf(root.path("system"));
            int inputChars = lengthOf(root.path("messages"));
            return new RequestView(model, toolCount, systemChars, inputChars);
        } catch (Exception ignored) {
            return RequestView.unparseable();
        }
    }

    @Override
    public ContinuationExtraction extractContinuation(byte[] body) {
        return JsonContinuationSupport.extract(mapper, PROVIDER, body, this::collectContinuation);
    }

    @Override
    public ContinuationTransformation transformContinuation(
            ContinuationView view, List<ReplacementEdit> edits, String fixedDirective) {
        return JsonContinuationSupport.transform(mapper, PROVIDER, view, edits, fixedDirective,
                this::collectContinuation, this::writeDirective);
    }

    private void writeDirective(com.fasterxml.jackson.databind.node.ObjectNode root,
                                String directive) {
        JsonNode system = root.get("system");
        if (system == null || system.isNull()) {
            root.put("system", directive);
            return;
        }
        if (system.isTextual()) {
            root.put("system", directive + "\n\n" + system.textValue());
            return;
        }
        if (system instanceof com.fasterxml.jackson.databind.node.ArrayNode blocks) {
            com.fasterxml.jackson.databind.node.ObjectNode block = mapper.createObjectNode();
            block.put("type", "text");
            block.put("text", directive);
            blocks.insert(0, block);
            return;
        }
        throw JsonContinuationSupport.unsupported();
    }

    private void collectContinuation(com.fasterxml.jackson.databind.node.ObjectNode root,
                                     JsonContinuationSupport.SegmentCollector segments) {
        JsonContinuationSupport.requireOnlyFields(root, ROOT_FIELDS);
        JsonNode model = root.get("model");
        JsonNode messages = root.get("messages");
        if (model == null || !model.isTextual() || model.textValue().isBlank()
                || !(messages instanceof com.fasterxml.jackson.databind.node.ArrayNode blocks)) {
            throw JsonContinuationSupport.malformed();
        }

        JsonNode system = root.get("system");
        if (system != null && !system.isNull()) {
            collectSystem(root, system, segments);
        }
        for (JsonNode message : blocks) {
            collectMessage(message, segments);
        }
    }

    private void collectSystem(com.fasterxml.jackson.databind.node.ObjectNode root, JsonNode system,
                               JsonContinuationSupport.SegmentCollector segments) {
        if (system.isTextual()) {
            segments.add(root, "system");
            return;
        }
        if (!(system instanceof com.fasterxml.jackson.databind.node.ArrayNode blocks)) {
            throw JsonContinuationSupport.unsupported();
        }
        for (JsonNode block : blocks) {
            if (!(block instanceof com.fasterxml.jackson.databind.node.ObjectNode object)
                    || !"text".equals(object.path("type").asText(""))) {
                throw JsonContinuationSupport.unsupported();
            }
            JsonContinuationSupport.requireOnlyFields(object, TEXT_BLOCK_FIELDS);
            segments.add(object, "text");
        }
    }

    private void collectMessage(JsonNode message,
                                JsonContinuationSupport.SegmentCollector segments) {
        if (!(message instanceof com.fasterxml.jackson.databind.node.ObjectNode object)
                || !MESSAGE_ROLES.contains(object.path("role").asText(""))) {
            throw JsonContinuationSupport.unsupported();
        }
        JsonContinuationSupport.requireOnlyFields(object, MESSAGE_FIELDS);
        String role = object.path("role").asText();
        JsonNode content = object.get("content");
        if (content == null || content.isNull()) {
            throw JsonContinuationSupport.malformed();
        }
        if (content.isTextual()) {
            segments.add(object, "content");
            return;
        }
        if (!(content instanceof com.fasterxml.jackson.databind.node.ArrayNode blocks)) {
            throw JsonContinuationSupport.unsupported();
        }
        for (JsonNode block : blocks) {
            collectContentBlock(role, block, segments);
        }
    }

    private void collectContentBlock(String role, JsonNode block,
                                     JsonContinuationSupport.SegmentCollector segments) {
        if (!(block instanceof com.fasterxml.jackson.databind.node.ObjectNode object)) {
            throw JsonContinuationSupport.unsupported();
        }
        switch (object.path("type").asText("")) {
            case "text" -> {
                JsonContinuationSupport.requireOnlyFields(object, TEXT_BLOCK_FIELDS);
                segments.add(object, "text");
            }
            case "tool_use" -> {
                JsonContinuationSupport.requireOnlyFields(object, TOOL_USE_FIELDS);
                if (!"assistant".equals(role)
                        || !object.path("id").isTextual() || !object.path("name").isTextual()
                        || !object.path("input").isObject()) {
                    throw JsonContinuationSupport.unsupported();
                }
                segments.addTree(object.path("input"));
            }
            case "tool_result" -> {
                JsonContinuationSupport.requireOnlyFields(object, TOOL_RESULT_FIELDS);
                if (!"user".equals(role)) {
                    throw JsonContinuationSupport.unsupported();
                }
                collectToolResult(object, segments);
            }
            // Anthropic requires signed thinking blocks in tool-use history to be
            // round-tripped complete and unmodified. They are deliberately not
            // editable content segments; the mandatory complete final policy scan
            // still fails closed if protected content remains anywhere in the body.
            case "thinking" -> {
                JsonContinuationSupport.requireOnlyFields(object, THINKING_FIELDS);
                if (!"assistant".equals(role) || !object.path("thinking").isTextual()
                        || !object.path("signature").isTextual()) {
                    throw JsonContinuationSupport.unsupported();
                }
            }
            case "redacted_thinking" -> {
                JsonContinuationSupport.requireOnlyFields(object, REDACTED_THINKING_FIELDS);
                if (!"assistant".equals(role) || !object.path("data").isTextual()) {
                    throw JsonContinuationSupport.unsupported();
                }
            }
            default -> throw JsonContinuationSupport.unsupported();
        }
    }

    private void collectToolResult(com.fasterxml.jackson.databind.node.ObjectNode result,
                                   JsonContinuationSupport.SegmentCollector segments) {
        if (!result.path("tool_use_id").isTextual()) {
            throw JsonContinuationSupport.unsupported();
        }
        JsonNode content = result.get("content");
        if (content == null || content.isNull()) {
            throw JsonContinuationSupport.malformed();
        }
        if (content.isTextual()) {
            segments.add(result, "content");
            return;
        }
        if (!(content instanceof com.fasterxml.jackson.databind.node.ArrayNode blocks)) {
            throw JsonContinuationSupport.unsupported();
        }
        for (JsonNode block : blocks) {
            if (!(block instanceof com.fasterxml.jackson.databind.node.ObjectNode object)
                    || !"text".equals(object.path("type").asText(""))) {
                throw JsonContinuationSupport.unsupported();
            }
            JsonContinuationSupport.requireOnlyFields(object, TEXT_BLOCK_FIELDS);
            segments.add(object, "text");
        }
    }

    @Override
    public NormalizedTurn finalizeTurn(TurnDraft draft) {
        Accum a = parse(draft.responseBody());
        String requestedModel = draft.request() == null ? null : draft.request().requestedModel();
        String servedModel = a.servedModel != null ? a.servedModel : requestedModel;

        long cached = a.cacheReadTokens;                              // cache hits
        long input = a.inputTokens + a.cacheReadTokens + a.cacheCreationTokens; // cached ⊆ input
        cached = Math.min(cached, input);
        long output = a.outputTokens;
        long reasoning = 0;                                          // counted within output for Anthropic
        long total = input + output;
        long uncached = input - cached;

        return new NormalizedTurn(
                draft.turnId(), draft.sessionId(),
                draft.agent() == null ? "unknown" : draft.agent(),
                PROVIDER, requestedModel, servedModel, a.status,
                input, cached, uncached, output, reasoning, total, a.toolCalls,
                List.of(), Action.FLAG, draft.durationMs(), Instant.now(),
                draft.requestId(), draft.requestBytesReceived(), draft.requestBytesInspected(),
                draft.requestBytesEgressed(), draft.edmDistinctCounts());
    }

    private Accum parse(byte[] body) {
        Accum a = new Accum();
        if (body == null || body.length == 0) {
            return a;
        }
        String text = new String(body, StandardCharsets.UTF_8);
        String trimmed = text.stripLeading();
        if (trimmed.startsWith("{")) {
            return parseJsonMessage(trimmed, a);
        }
        for (String block : splitSseBlocks(text)) {
            String data = extractData(block);
            if (data == null || data.strip().equals("[DONE]")) {
                continue;
            }
            try {
                JsonNode node = mapper.readTree(data.strip());
                switch (node.path("type").asText("")) {
                    case "message_start" -> applyMessageStart(a, node.path("message"));
                    case "content_block_start" -> {
                        if (node.path("content_block").path("type").asText("").equals("tool_use")) {
                            a.toolCalls++;
                        }
                    }
                    case "message_delta" -> applyMessageDelta(a, node);
                    default -> { /* content_block_delta, ping, message_stop: ignored */ }
                }
            } catch (Exception ignored) {
                // Content-free parse failure; malformed blocks contribute no accounting.
            }
        }
        return a;
    }

    private Accum parseJsonMessage(String text, Accum a) {
        try {
            JsonNode message = mapper.readTree(text);
            if (message.has("error")) {
                a.status = "failed";
                return a;
            }
            applyJsonMessage(a, message);
        } catch (Exception ignored) {
            // Content-free parse failure; malformed responses contribute no accounting.
        }
        return a;
    }

    private static void applyMessageStart(Accum a, JsonNode message) {
        if (message.hasNonNull("model")) {
            a.servedModel = message.get("model").asText();
        }
        JsonNode usage = message.path("usage");
        a.inputTokens = usage.path("input_tokens").asLong(0);
        a.cacheReadTokens = usage.path("cache_read_input_tokens").asLong(0);
        a.cacheCreationTokens = usage.path("cache_creation_input_tokens").asLong(0);
        a.outputTokens = usage.path("output_tokens").asLong(a.outputTokens);
    }

    private static void applyJsonMessage(Accum a, JsonNode message) {
        if (message.hasNonNull("model")) {
            a.servedModel = message.get("model").asText();
        }
        JsonNode usage = message.path("usage");
        a.inputTokens = usage.path("input_tokens").asLong(0);
        a.cacheReadTokens = usage.path("cache_read_input_tokens").asLong(0);
        a.cacheCreationTokens = usage.path("cache_creation_input_tokens").asLong(0);
        a.outputTokens = usage.path("output_tokens").asLong(0);
        JsonNode content = message.path("content");
        if (content.isArray()) {
            for (JsonNode block : content) {
                if (block.path("type").asText("").equals("tool_use")) {
                    a.toolCalls++;
                }
            }
        }
        String stopReason = message.path("stop_reason").asText(null);
        a.status = "max_tokens".equals(stopReason) ? "incomplete" : "completed";
    }

    private static void applyMessageDelta(Accum a, JsonNode node) {
        JsonNode usage = node.path("usage");
        if (usage.has("output_tokens")) {
            a.outputTokens = usage.path("output_tokens").asLong(a.outputTokens);
        }
        String stopReason = node.path("delta").path("stop_reason").asText(null);
        if (stopReason != null) {
            a.status = "max_tokens".equals(stopReason) ? "incomplete" : "completed";
        }
    }

    private static String extractData(String block) {
        StringBuilder data = null;
        for (String line : block.split("\\R")) {
            if (line.startsWith("data:")) {
                String part = line.substring("data:".length()).stripLeading();
                data = data == null ? new StringBuilder(part) : data.append('\n').append(part);
            }
        }
        return data == null ? null : data.toString();
    }

    private static String[] splitSseBlocks(String text) {
        return text.split("\\R\\s*\\R");
    }

    private static int lengthOf(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return 0;
        }
        return node.isTextual() ? node.asText().length() : node.toString().length();
    }

    private static final class Accum {
        String status = "unknown";
        String servedModel;
        long inputTokens;
        long cacheReadTokens;
        long cacheCreationTokens;
        long outputTokens;
        int toolCalls;
    }
}
