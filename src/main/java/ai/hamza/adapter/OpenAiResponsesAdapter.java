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
 * Adapter for the OpenAI Responses wire format (Codex CLI / OpenAI Responses SSE).
 *
 * <p>Request: model, tools, instructions/input lengths. Response: an SSE stream of
 * {@code response.created}, {@code response.output_item.*}, and a terminal
 * {@code response.completed|failed|incomplete} carrying {@code usage}. Token math is
 * read straight from the wire — the cost signal OTEL hides.
 */
@Component
public class OpenAiResponsesAdapter implements ProviderAdapter {

    private static final String PROVIDER = "openai";
    private static final ProviderSpec SPEC = new ProviderSpec(PROVIDER,
            List.of("api.openai.com", "chatgpt.com"),
            List.of("/v1/responses", "/responses", "/backend-api/codex/responses"));
    private static final Set<String> MESSAGE_ROLES = Set.of(
            "developer", "system", "user", "assistant");
    private static final Set<String> TEXT_BLOCK_TYPES = Set.of("input_text", "output_text");
    private static final Set<String> ROOT_FIELDS = Set.of(
            "background", "conversation", "include", "input", "instructions",
            "max_output_tokens", "max_tool_calls", "metadata", "model",
            "parallel_tool_calls", "previous_response_id", "prompt", "prompt_cache_key",
            "prompt_cache_retention", "reasoning", "safety_identifier", "service_tier",
            "store", "stream", "stream_options", "temperature", "text", "tool_choice",
            "tools", "top_logprobs", "top_p", "truncation", "user", "client_metadata");
    private static final Set<String> MESSAGE_FIELDS = Set.of(
            "type", "role", "content", "id", "status", "phase",
            "internal_chat_message_metadata_passthrough");
    private static final Set<String> TEXT_BLOCK_FIELDS = Set.of(
            "type", "text", "annotations", "logprobs");
    private static final Set<String> FUNCTION_OUTPUT_FIELDS = Set.of(
            "type", "call_id", "output", "id", "status",
            "internal_chat_message_metadata_passthrough");
    private static final Set<String> REASONING_FIELDS = Set.of(
            "type", "id", "summary", "content", "encrypted_content", "status",
            "internal_chat_message_metadata_passthrough");
    private static final Set<String> FUNCTION_CALL_FIELDS = Set.of(
            "type", "id", "name", "namespace", "arguments", "call_id", "status",
            "internal_chat_message_metadata_passthrough");
    private static final Set<String> CUSTOM_CALL_FIELDS = Set.of(
            "type", "id", "name", "namespace", "input", "call_id", "status",
            "internal_chat_message_metadata_passthrough");

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
        // OpenAI Responses API paths: /v1/responses, /responses,
        // /backend-api/codex/responses, ... — all contain "/responses".
        return path != null && path.contains("/responses");
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
            int instructionChars = lengthOf(root.path("instructions"));
            int inputChars = lengthOf(root.path("input"));
            return new RequestView(model, toolCount, instructionChars, inputChars);
        } catch (Exception ignored) {
            // Malformed or non-JSON body on a matched path: report it so the Gate can
            // raise a wire-drift Finding instead of silently degrading.
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
        JsonNode instructions = root.get("instructions");
        if (instructions == null || instructions.isNull()) {
            root.put("instructions", directive);
            return;
        }
        if (!instructions.isTextual()) {
            throw JsonContinuationSupport.unsupported();
        }
        root.put("instructions", directive + "\n\n" + instructions.textValue());
    }

    private void collectContinuation(com.fasterxml.jackson.databind.node.ObjectNode root,
                                     JsonContinuationSupport.SegmentCollector segments) {
        JsonContinuationSupport.requireOnlyFields(root, ROOT_FIELDS);
        JsonNode model = root.get("model");
        if (model == null || !model.isTextual() || model.textValue().isBlank()) {
            throw JsonContinuationSupport.malformed();
        }

        JsonNode instructions = root.get("instructions");
        if (instructions != null && !instructions.isNull()) {
            if (!instructions.isTextual()) {
                throw JsonContinuationSupport.unsupported();
            }
            segments.add(root, "instructions");
        }

        JsonNode input = root.get("input");
        if (input == null || input.isNull()) {
            throw JsonContinuationSupport.malformed();
        }
        if (input.isTextual()) {
            segments.add(root, "input");
            return;
        }
        if (!input.isArray()) {
            throw JsonContinuationSupport.unsupported();
        }
        for (JsonNode item : input) {
            collectInputItem(item, segments);
        }
    }

    private void collectInputItem(JsonNode item,
                                  JsonContinuationSupport.SegmentCollector segments) {
        if (!(item instanceof com.fasterxml.jackson.databind.node.ObjectNode object)) {
            throw JsonContinuationSupport.unsupported();
        }
        String type = object.path("type").asText("");
        if ("message".equals(type)) {
            JsonContinuationSupport.requireOnlyFields(object, MESSAGE_FIELDS);
            collectMessage(object, segments);
            return;
        }
        if ("function_call_output".equals(type) || "custom_tool_call_output".equals(type)) {
            JsonContinuationSupport.requireOnlyFields(object, FUNCTION_OUTPUT_FIELDS);
            segments.add(object, "output");
            return;
        }
        if ("reasoning".equals(type)) {
            JsonContinuationSupport.requireOnlyFields(object, REASONING_FIELDS);
            return;
        }
        if ("function_call".equals(type)) {
            JsonContinuationSupport.requireOnlyFields(object, FUNCTION_CALL_FIELDS);
            if (!object.path("arguments").isTextual()) {
                throw JsonContinuationSupport.unsupported();
            }
            segments.add(object, "arguments");
            return;
        }
        if ("custom_tool_call".equals(type)) {
            JsonContinuationSupport.requireOnlyFields(object, CUSTOM_CALL_FIELDS);
            JsonNode input = object.get("input");
            if (input == null || input.isNull()) {
                throw JsonContinuationSupport.malformed();
            }
            if (input.isTextual()) {
                segments.add(object, "input");
            } else if (input.isContainerNode()) {
                segments.addTree(input);
            } else {
                throw JsonContinuationSupport.unsupported();
            }
            return;
        }
        throw JsonContinuationSupport.unsupported();
    }

    private void collectMessage(com.fasterxml.jackson.databind.node.ObjectNode message,
                                JsonContinuationSupport.SegmentCollector segments) {
        if (!MESSAGE_ROLES.contains(message.path("role").asText(""))) {
            throw JsonContinuationSupport.unsupported();
        }
        JsonNode content = message.get("content");
        if (content == null || content.isNull()) {
            throw JsonContinuationSupport.malformed();
        }
        if (content.isTextual()) {
            segments.add(message, "content");
            return;
        }
        if (!(content instanceof com.fasterxml.jackson.databind.node.ArrayNode blocks)) {
            throw JsonContinuationSupport.unsupported();
        }
        for (JsonNode block : blocks) {
            if (!(block instanceof com.fasterxml.jackson.databind.node.ObjectNode object)
                    || !TEXT_BLOCK_TYPES.contains(object.path("type").asText(""))) {
                throw JsonContinuationSupport.unsupported();
            }
            JsonContinuationSupport.requireOnlyFields(object, TEXT_BLOCK_FIELDS);
            segments.add(object, "text");
        }
    }

    @Override
    public NormalizedTurn finalizeTurn(TurnDraft draft) {
        SseResult sse = parseResponse(draft.responseBody());
        String requestedModel = draft.request() == null ? null : draft.request().requestedModel();
        String servedModel = sse.servedModel != null ? sse.servedModel : requestedModel;

        long input = sse.inputTokens;
        long cached = Math.min(sse.cachedTokens, input);          // cached ⊆ input
        long output = sse.outputTokens;
        long reasoning = Math.min(sse.reasoningTokens, output);   // reasoning ⊆ output
        long total = sse.totalTokens > 0 ? sse.totalTokens : input + output;
        long uncached = input - cached;

        return new NormalizedTurn(
                draft.turnId(),
                draft.sessionId(),
                draft.agent() == null ? "unknown" : draft.agent(),
                PROVIDER,
                requestedModel,
                servedModel,
                sse.status,
                input,
                cached,
                uncached,
                output,
                reasoning,
                total,
                sse.toolCalls,
                List.of(),          // Findings arrive with the policy engine (M4)
                Action.FLAG,        // default Posture: observe
                draft.durationMs(),
                Instant.now(),
                draft.requestId(),
                draft.requestBytesReceived(),
                draft.requestBytesInspected(),
                draft.requestBytesEgressed(),
                draft.edmDistinctCounts());
    }

    private SseResult parseResponse(byte[] body) {
        SseResult result = new SseResult();
        if (body == null || body.length == 0) {
            return result;
        }
        String text = new String(body, StandardCharsets.UTF_8);
        // SSE events are separated by a blank line; each has one or more data: lines.
        for (String block : splitSseBlocks(text)) {
            String data = extractData(block);
            if (data == null || data.strip().equals("[DONE]")) {
                continue;
            }
            try {
                JsonNode node = mapper.readTree(data.strip());
                String type = node.path("type").asText("");
                if (type.equals("response.output_item.added")) {
                    if (isToolCall(node.path("item"))) {
                        result.toolCalls++;
                    }
                } else if (type.startsWith("response.") && isTerminal(type)) {
                    applyTerminal(result, type, node.path("response"));
                }
            } catch (Exception ignored) {
                // Content-free parse failure; malformed blocks contribute no accounting.
            }
        }
        return result;
    }

    private static boolean isTerminal(String type) {
        return type.equals("response.completed")
                || type.equals("response.failed")
                || type.equals("response.incomplete");
    }

    private static void applyTerminal(SseResult result, String type, JsonNode response) {
        result.status = type.substring("response.".length()); // completed | failed | incomplete
        if (response.hasNonNull("model")) {
            result.servedModel = response.get("model").asText();
        }
        JsonNode usage = response.path("usage");
        if (usage.isObject()) {
            result.inputTokens = usage.path("input_tokens").asLong(0);
            result.cachedTokens = usage.path("input_tokens_details").path("cached_tokens").asLong(0);
            result.outputTokens = usage.path("output_tokens").asLong(0);
            result.reasoningTokens = usage.path("output_tokens_details").path("reasoning_tokens").asLong(0);
            result.totalTokens = usage.path("total_tokens").asLong(0);
        }
    }

    private static boolean isToolCall(JsonNode item) {
        String t = item.path("type").asText("");
        return t.contains("function_call") || t.contains("tool") || t.endsWith("_call");
    }

    private static String extractData(String block) {
        StringBuilder data = null;
        for (String line : block.split("\\R")) {
            if (line.startsWith("data:")) {
                String part = line.substring("data:".length()).stripLeading();
                if (data == null) {
                    data = new StringBuilder(part);
                } else {
                    data.append('\n').append(part);
                }
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
        if (node.isTextual()) {
            return node.asText().length();
        }
        // Arrays/objects (e.g. structured input): count their serialized size as a
        // cheap, content-free magnitude signal.
        return node.toString().length();
    }

    /** Mutable accumulator for one response parse. */
    private static final class SseResult {
        String status = "unknown";
        String servedModel;
        long inputTokens;
        long cachedTokens;
        long outputTokens;
        long reasoningTokens;
        long totalTokens;
        int toolCalls;
    }
}
