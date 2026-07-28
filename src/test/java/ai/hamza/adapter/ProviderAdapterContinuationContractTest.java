package ai.hamza.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class ProviderAdapterContinuationContractTest {

    private static final String PROTECTED = "priya.fixture@example-corp.test";
    private static final String SUBSTITUTE = "hamza-0123456789abcdef0123456789abcdef@example.invalid";
    private static final String DIRECTIVE = "HAMZA SAFE CONTINUATION V1: use synthetic values only.";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static byte[] fixture(String name) {
        try (var in = ProviderAdapterContinuationContractTest.class
                .getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalArgumentException("fixture not found: " + name);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Test
    void openAiExtractsOnlyApprovedDecodedContentThroughTheCommonSeam() {
        ProviderAdapter adapter = new OpenAiResponsesAdapter();

        ContinuationExtraction extraction = adapter.extractContinuation(
                fixture("openai-responses-request-v1.json"));

        assertThat(extraction).isInstanceOf(ContinuationExtraction.Valid.class);
        ContinuationView view = ((ContinuationExtraction.Valid) extraction).view();
        assertThat(view.provider()).isEqualTo("openai");
        assertThat(view.segments()).extracting(ContentSegment::text)
                .containsExactly(
                        "Work safely with " + PROTECTED + ".",
                        "Review \"café\" for " + PROTECTED + ".",
                        "lookup returned " + PROTECTED,
                        "{\"email\":\"synthetic@example.invalid\"}");
        assertThat(view.segments()).extracting(ContentSegment::id)
                .containsExactly("segment-0", "segment-1", "segment-2", "segment-3");
        assertThat(view.segments()).allSatisfy(segment ->
                assertThat(segment.text()).doesNotContain("lookup_example", "call_example_1"));
        assertThat(view.segments()).isUnmodifiable();
    }

    @Test
    void openAiTransformsEveryRepeatedOccurrenceAndPreservesTheWireStructure() throws Exception {
        ProviderAdapter adapter = new OpenAiResponsesAdapter();
        byte[] originalBody = fixture("openai-responses-request-v1.json");
        ContinuationView view = validView(adapter, originalBody);

        ContinuationTransformation transformation = adapter.transformContinuation(
                view, editsForEveryOccurrence(view, PROTECTED, SUBSTITUTE), DIRECTIVE);

        assertThat(transformation).isInstanceOf(ContinuationTransformation.Success.class);
        byte[] transformedBody = ((ContinuationTransformation.Success) transformation).body();
        JsonNode before = MAPPER.readTree(originalBody);
        JsonNode after = MAPPER.readTree(transformedBody);

        assertThat(new String(transformedBody, StandardCharsets.UTF_8)).doesNotContain(PROTECTED);
        assertThat(after.path("instructions").asText())
                .isEqualTo(DIRECTIVE + "\n\nWork safely with " + SUBSTITUTE + ".");
        assertThat(after.path("input").path(0).path("content").path(0).path("text").asText())
                .isEqualTo("Review \"café\" for " + SUBSTITUTE + ".");
        assertThat(after.path("input").path(1).path("output").asText())
                .isEqualTo("lookup returned " + SUBSTITUTE);

        for (String field : List.of("model", "tools", "tool_choice", "parallel_tool_calls",
                "stream", "store", "metadata")) {
            assertThat(after.get(field)).as(field).isEqualTo(before.get(field));
        }
        assertThat(after.path("input").path(0).path("type"))
                .isEqualTo(before.path("input").path(0).path("type"));
        assertThat(after.path("input").path(0).path("role"))
                .isEqualTo(before.path("input").path(0).path("role"));
        assertThat(after.path("input").path(1).path("call_id"))
                .isEqualTo(before.path("input").path(1).path("call_id"));
        assertThat(after.path("input").path(2)).isEqualTo(before.path("input").path(2));
        assertThat(after.path("input").path(3)).isEqualTo(before.path("input").path(3));

        transformedBody[0] = (byte) 'x';
        assertThat(((ContinuationTransformation.Success) transformation).body()[0])
                .isEqualTo((byte) '{');
    }

    @Test
    void anthropicExtractsAndTransformsSupportedToolResultContentThroughTheCommonSeam()
            throws Exception {
        ProviderAdapter adapter = new AnthropicMessagesAdapter();
        byte[] originalBody = fixture("anthropic-messages-request-v1.json");
        ContinuationView view = validView(adapter, originalBody);

        assertThat(view.provider()).isEqualTo("anthropic");
        assertThat(view.segments()).extracting(ContentSegment::text)
                .containsExactly(
                        "Follow policy for " + PROTECTED + ".",
                        "Check " + PROTECTED + ".",
                        "I will inspect \"café\" for " + PROTECTED + ".",
                        "synthetic-request@example.invalid",
                        "result for " + PROTECTED);

        ContinuationTransformation transformation = adapter.transformContinuation(
                view, editsForEveryOccurrence(view, PROTECTED, SUBSTITUTE), DIRECTIVE);

        assertThat(transformation).isInstanceOf(ContinuationTransformation.Success.class);
        JsonNode before = MAPPER.readTree(originalBody);
        JsonNode after = MAPPER.readTree(
                ((ContinuationTransformation.Success) transformation).body());
        assertThat(after.path("system")).hasSize(2);
        assertThat(after.path("system").path(0).path("type").asText()).isEqualTo("text");
        assertThat(after.path("system").path(0).path("text").asText()).isEqualTo(DIRECTIVE);
        assertThat(after.path("system").path(1).path("text").asText())
                .isEqualTo("Follow policy for " + SUBSTITUTE + ".");
        assertThat(after.path("messages").path(0).path("content").asText())
                .isEqualTo("Check " + SUBSTITUTE + ".");
        assertThat(after.path("messages").path(1).path("content").path(0).path("text").asText())
                .isEqualTo("I will inspect \"café\" for " + SUBSTITUTE + ".");
        assertThat(after.path("messages").path(2).path("content").path(0)
                .path("content").path(0).path("text").asText())
                .isEqualTo("result for " + SUBSTITUTE);

        for (String field : List.of("model", "max_tokens", "tools", "temperature",
                "stream", "metadata")) {
            assertThat(after.get(field)).as(field).isEqualTo(before.get(field));
        }
        assertThat(after.path("messages").path(1).path("content").path(1))
                .isEqualTo(before.path("messages").path(1).path("content").path(1));
        assertThat(after.path("messages").path(2).path("content").path(0)
                .path("tool_use_id"))
                .isEqualTo(before.path("messages").path(2).path("content").path(0)
                        .path("tool_use_id"));
    }

    @Test
    void anthropicPreservesSignedThinkingBlocksWhileTransformingText() throws Exception {
        ProviderAdapter adapter = new AnthropicMessagesAdapter();
        byte[] originalBody = ("""
                {"model":"claude-haiku-4-5-20251001","max_tokens":4096,
                 "thinking":{"type":"enabled","budget_tokens":1024},
                 "messages":[
                   {"role":"user","content":"Review %s"},
                   {"role":"assistant","content":[
                     {"type":"thinking","thinking":"content-free summary",\
                      "signature":"fake-signature-for-example.invalid"},
                     {"type":"redacted_thinking","data":"fake-encrypted-data"},
                     {"type":"tool_use","id":"toolu_fake","name":"read_fixture",\
                      "input":{"path":"records.txt"}}]},
                   {"role":"user","content":[
                     {"type":"tool_result","tool_use_id":"toolu_fake",\
                      "content":"result for %s"}]}],
                 "tools":[],"stream":true}
                """).formatted(PROTECTED, PROTECTED).getBytes(StandardCharsets.UTF_8);
        ContinuationView view = validView(adapter, originalBody);

        ContinuationTransformation transformation = adapter.transformContinuation(
                view, editsForEveryOccurrence(view, PROTECTED, SUBSTITUTE), DIRECTIVE);

        assertThat(transformation).isInstanceOf(ContinuationTransformation.Success.class);
        JsonNode before = MAPPER.readTree(originalBody);
        JsonNode after = MAPPER.readTree(
                ((ContinuationTransformation.Success) transformation).body());
        assertThat(after.path("messages").path(1).path("content").path(0))
                .isEqualTo(before.path("messages").path(1).path("content").path(0));
        assertThat(after.path("messages").path(1).path("content").path(1))
                .isEqualTo(before.path("messages").path(1).path("content").path(1));
        assertThat(after.toString()).doesNotContain(PROTECTED)
                .contains(SUBSTITUTE, DIRECTIVE);
    }

    @Test
    void openAiRejectsUnknownTopLevelWireFields() throws Exception {
        var body = (com.fasterxml.jackson.databind.node.ObjectNode) MAPPER.readTree(
                fixture("openai-responses-request-v1.json"));
        body.put("future_unknown_option", "must fail closed");

        assertThat(new OpenAiResponsesAdapter().extractContinuation(
                MAPPER.writeValueAsBytes(body)))
                .isInstanceOf(ContinuationExtraction.Unsupported.class);
    }

    @Test
    void anthropicRejectsUnknownTopLevelWireFields() throws Exception {
        var body = (com.fasterxml.jackson.databind.node.ObjectNode) MAPPER.readTree(
                fixture("anthropic-messages-request-v1.json"));
        body.put("future_unknown_option", "must fail closed");

        assertThat(new AnthropicMessagesAdapter().extractContinuation(
                MAPPER.writeValueAsBytes(body)))
                .isInstanceOf(ContinuationExtraction.Unsupported.class);
    }

    @Test
    void openAiRejectsUnknownNestedWireFields() throws Exception {
        var body = (com.fasterxml.jackson.databind.node.ObjectNode) MAPPER.readTree(
                fixture("openai-responses-request-v1.json"));
        ((com.fasterxml.jackson.databind.node.ObjectNode) body.path("input").path(0))
                .put("future_unknown_item_field", "must fail closed");

        assertThat(new OpenAiResponsesAdapter().extractContinuation(
                MAPPER.writeValueAsBytes(body)))
                .isInstanceOf(ContinuationExtraction.Unsupported.class);
    }

    @Test
    void openAiAcceptsCodex0144CertifiedOptionalFields() throws Exception {
        var body = (com.fasterxml.jackson.databind.node.ObjectNode) MAPPER.readTree(
                fixture("openai-responses-request-v1.json"));
        body.putObject("client_metadata").put("origin", "codex-cli");
        var message = (com.fasterxml.jackson.databind.node.ObjectNode)
                body.path("input").path(0);
        message.put("phase", "commentary");
        message.putObject("internal_chat_message_metadata_passthrough")
                .put("turn_id", "fixture-turn");
        var output = (com.fasterxml.jackson.databind.node.ObjectNode)
                body.path("input").path(1);
        output.putObject("internal_chat_message_metadata_passthrough")
                .put("turn_id", "fixture-turn");
        var reasoning = (com.fasterxml.jackson.databind.node.ObjectNode)
                body.path("input").path(2);
        reasoning.putArray("content").addObject()
                .put("type", "reasoning_text").put("text", "content-free summary");
        var call = (com.fasterxml.jackson.databind.node.ObjectNode)
                body.path("input").path(3);
        call.put("namespace", "functions");

        ContinuationExtraction extraction = new OpenAiResponsesAdapter()
                .extractContinuation(MAPPER.writeValueAsBytes(body));

        assertThat(extraction).isInstanceOf(ContinuationExtraction.Valid.class);
    }

    @Test
    void anthropicRejectsUnknownNestedWireFields() throws Exception {
        var body = (com.fasterxml.jackson.databind.node.ObjectNode) MAPPER.readTree(
                fixture("anthropic-messages-request-v1.json"));
        ((com.fasterxml.jackson.databind.node.ObjectNode) body.path("messages").path(0))
                .put("future_unknown_message_field", "must fail closed");

        assertThat(new AnthropicMessagesAdapter().extractContinuation(
                MAPPER.writeValueAsBytes(body)))
                .isInstanceOf(ContinuationExtraction.Unsupported.class);
    }

    private static ContinuationView validView(ProviderAdapter adapter, byte[] body) {
        ContinuationExtraction extraction = adapter.extractContinuation(body);
        assertThat(extraction).isInstanceOf(ContinuationExtraction.Valid.class);
        return ((ContinuationExtraction.Valid) extraction).view();
    }

    private static List<ReplacementEdit> editsForEveryOccurrence(
            ContinuationView view, String original, String replacement) {
        List<ReplacementEdit> edits = new ArrayList<>();
        for (ContentSegment segment : view.segments()) {
            int from = 0;
            while (from <= segment.text().length() - original.length()) {
                int start = segment.text().indexOf(original, from);
                if (start < 0) {
                    break;
                }
                edits.add(new ReplacementEdit(segment.id(), start,
                        start + original.length(), replacement));
                from = start + original.length();
            }
        }
        return List.copyOf(edits);
    }
}
