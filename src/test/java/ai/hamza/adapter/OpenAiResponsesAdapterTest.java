package ai.hamza.adapter;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for the OpenAI Responses Adapter: matching, request parse, token math, status. */
class OpenAiResponsesAdapterTest {

    private final OpenAiResponsesAdapter adapter = new OpenAiResponsesAdapter();

    private static byte[] fixture(String name) {
        try (var in = OpenAiResponsesAdapterTest.class.getResourceAsStream("/fixtures/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing fixture " + name);
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private TurnDraft draft(byte[] responseBody, String requestedModel) {
        return new TurnDraft("turn-1", "sess-1", "codex",
                new RequestView(requestedModel, 0, 0, 0), 200, responseBody, 42L);
    }

    @Test
    void peekModelExtractsTopLevelModelFromTruncatedPrefix() {
        // A prefix cut off mid-body (oversize) still yields the requested model, which is
        // near the start of the JSON — parseRequest would fail on the truncated JSON.
        byte[] truncated = "{\"model\":\"gpt-5-codex\",\"input\":\"a very long prompt that is cut off"
                .getBytes(StandardCharsets.UTF_8);
        assertThat(adapter.peekModel(truncated)).contains("gpt-5-codex");
        assertThat(adapter.parseRequest(truncated).requestedModel())
                .as("full parse fails on truncated JSON, so peekModel is needed").isNull();
    }

    @Test
    void peekModelIgnoresNestedModelAndMissingModel() {
        // A nested "model" (inside input) is not the requested model.
        byte[] nestedOnly = "{\"input\":[{\"model\":\"nested\"}],\"stream\":true}"
                .getBytes(StandardCharsets.UTF_8);
        assertThat(adapter.peekModel(nestedOnly)).isEmpty();
        assertThat(adapter.peekModel("not json".getBytes(StandardCharsets.UTF_8))).isEmpty();
        assertThat(adapter.peekModel(new byte[0])).isEmpty();
    }

    @Test
    void matchesResponsesPaths() {
        assertThat(adapter.matches("/v1/responses", Map.of())).isTrue();
        assertThat(adapter.matches("/backend-api/codex/responses", Map.of())).isTrue();
        assertThat(adapter.matches("/v1/chat/completions", Map.of())).isFalse();
        assertThat(adapter.provider()).isEqualTo("openai");
        assertThat(adapter.spec().domains())
                .containsExactly("api.openai.com", "chatgpt.com");
    }

    @Test
    void parsesRequestModelAndCountsWithoutContent() {
        byte[] body = """
                {"model":"gpt-5-codex","instructions":"be brief",
                 "tools":[{"type":"function"},{"type":"function"}],
                 "input":"hello world"}
                """.getBytes(StandardCharsets.UTF_8);
        RequestView view = adapter.parseRequest(body);
        assertThat(view.requestedModel()).isEqualTo("gpt-5-codex");
        assertThat(view.toolCount()).isEqualTo(2);
        assertThat(view.instructionChars()).isEqualTo("be brief".length());
        assertThat(view.inputChars()).isEqualTo("hello world".length());
    }

    @Test
    void completedTurnHasCorrectTokenMath() {
        NormalizedTurn turn = adapter.finalizeTurn(draft(fixture("openai-responses-completed.sse"), "gpt-5-codex"));

        assertThat(turn.status()).isEqualTo("completed");
        assertThat(turn.provider()).isEqualTo("openai");
        assertThat(turn.requestedModel()).isEqualTo("gpt-5-codex");
        assertThat(turn.servedModel()).isEqualTo("gpt-5-codex");
        assertThat(turn.isModelFallback()).isFalse();

        // Token math invariants.
        assertThat(turn.inputTokens()).isEqualTo(120);
        assertThat(turn.cachedInputTokens()).isEqualTo(20);
        assertThat(turn.uncachedInputTokens()).isEqualTo(100);
        assertThat(turn.outputTokens()).isEqualTo(80);
        assertThat(turn.reasoningTokens()).isEqualTo(30);
        assertThat(turn.totalTokens()).isEqualTo(200);

        assertThat(turn.cachedInputTokens()).isLessThanOrEqualTo(turn.inputTokens());
        assertThat(turn.reasoningTokens()).isLessThanOrEqualTo(turn.outputTokens());
        assertThat(turn.totalTokens()).isEqualTo(turn.inputTokens() + turn.outputTokens());
        assertThat(turn.uncachedInputTokens()).isEqualTo(turn.inputTokens() - turn.cachedInputTokens());
    }

    @Test
    void clampsCachedAndReasoningToTheirSupersets() {
        // A misbehaving Provider reports cached > input and reasoning > output.
        String sse = """
                event: response.completed
                data: {"type":"response.completed","response":{"model":"m","status":"completed",\
                "usage":{"input_tokens":10,"input_tokens_details":{"cached_tokens":99},\
                "output_tokens":5,"output_tokens_details":{"reasoning_tokens":99}}}}

                data: [DONE]
                """;
        NormalizedTurn turn = adapter.finalizeTurn(draft(sse.getBytes(StandardCharsets.UTF_8), "m"));
        assertThat(turn.cachedInputTokens()).isEqualTo(10);   // clamped: cached ⊆ input
        assertThat(turn.reasoningTokens()).isEqualTo(5);      // clamped: reasoning ⊆ output
        assertThat(turn.totalTokens()).isEqualTo(15);         // total = input + output
    }

    @Test
    void detectsModelFallback() {
        String sse = """
                event: response.completed
                data: {"type":"response.completed","response":{"model":"gpt-5-mini","status":"completed",\
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}

                data: [DONE]
                """;
        NormalizedTurn turn = adapter.finalizeTurn(draft(sse.getBytes(StandardCharsets.UTF_8), "gpt-5-codex"));
        assertThat(turn.requestedModel()).isEqualTo("gpt-5-codex");
        assertThat(turn.servedModel()).isEqualTo("gpt-5-mini");
        assertThat(turn.isModelFallback()).isTrue();
    }

    @Test
    void parsesFailedAndIncompleteStatuses() {
        String failed = """
                event: response.failed
                data: {"type":"response.failed","response":{"model":"m","status":"failed"}}

                data: [DONE]
                """;
        assertThat(adapter.finalizeTurn(draft(failed.getBytes(StandardCharsets.UTF_8), "m")).status())
                .isEqualTo("failed");

        String incomplete = """
                event: response.incomplete
                data: {"type":"response.incomplete","response":{"model":"m","status":"incomplete"}}

                data: [DONE]
                """;
        assertThat(adapter.finalizeTurn(draft(incomplete.getBytes(StandardCharsets.UTF_8), "m")).status())
                .isEqualTo("incomplete");
    }

    @Test
    void malformedAndEmptySseDoNotInventAccounting() {
        NormalizedTurn empty = adapter.finalizeTurn(draft(new byte[0], "m"));
        assertThat(empty.status()).isEqualTo("unknown");
        assertThat(empty.servedModel()).isEqualTo("m");
        assertThat(empty.inputTokens()).isZero();
        assertThat(empty.outputTokens()).isZero();
        assertThat(empty.totalTokens()).isZero();

        String malformed = """
                event: response.completed
                data: {"type":

                data: [DONE]
                """;
        NormalizedTurn bad = adapter.finalizeTurn(draft(malformed.getBytes(StandardCharsets.UTF_8), "m"));
        assertThat(bad.status()).isEqualTo("unknown");
        assertThat(bad.totalTokens()).isZero();
    }

    @Test
    void countsToolCallOutputItems() {
        String sse = """
                event: response.output_item.added
                data: {"type":"response.output_item.added","item":{"type":"function_call","name":"shell"}}

                event: response.completed
                data: {"type":"response.completed","response":{"model":"m","status":"completed",\
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}

                data: [DONE]
                """;
        assertThat(adapter.finalizeTurn(draft(sse.getBytes(StandardCharsets.UTF_8), "m")).toolCalls())
                .isEqualTo(1);
    }
}
