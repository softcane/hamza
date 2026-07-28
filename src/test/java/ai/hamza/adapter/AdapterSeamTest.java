package ai.hamza.adapter;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M5: the Adapter seam. A second Provider (Anthropic Messages) normalises through the
 * same {@link NormalizedTurn} model and is selected by path — "write one Adapter, not
 * a rewrite." Token-math invariants hold identically across Providers.
 */
class AdapterSeamTest {

    private final OpenAiResponsesAdapter openai = new OpenAiResponsesAdapter();
    private final AnthropicMessagesAdapter anthropic = new AnthropicMessagesAdapter();

    private static byte[] fixture(String name) {
        try (var in = AdapterSeamTest.class.getResourceAsStream("/fixtures/" + name)) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private TurnDraft draft(byte[] body, String model) {
        return new TurnDraft("t", "s", "claude-code", new RequestView(model, 0, 0, 0), 200, body, 10L);
    }

    @Test
    void adaptersSelectByPathWithoutOverlap() {
        // One interface, many Agents: each Adapter claims only its own wire format.
        List<ProviderAdapter> adapters = List.of(openai, anthropic);

        ProviderAdapter forResponses = adapters.stream()
                .filter(a -> a.matches("/v1/responses", Map.of())).findFirst().orElseThrow();
        ProviderAdapter forMessages = adapters.stream()
                .filter(a -> a.matches("/v1/messages", Map.of())).findFirst().orElseThrow();

        assertThat(forResponses.provider()).isEqualTo("openai");
        assertThat(forMessages.provider()).isEqualTo("anthropic");
        assertThat(openai.matches("/v1/messages", Map.of())).isFalse();
        assertThat(anthropic.matches("/v1/responses", Map.of())).isFalse();
    }

    @Test
    void anthropicTurnNormalisesWithCorrectTokenMath() {
        NormalizedTurn turn = anthropic.finalizeTurn(
                draft(fixture("anthropic-messages-completed.sse"), "claude-sonnet-4-6"));

        assertThat(turn.provider()).isEqualTo("anthropic");
        assertThat(turn.servedModel()).isEqualTo("claude-sonnet-4-6");
        assertThat(turn.status()).isEqualTo("completed");

        // input = input_tokens(50) + cache_read(10) + cache_creation(0); cached = 10.
        assertThat(turn.inputTokens()).isEqualTo(60);
        assertThat(turn.cachedInputTokens()).isEqualTo(10);
        assertThat(turn.uncachedInputTokens()).isEqualTo(50);
        assertThat(turn.outputTokens()).isEqualTo(25);
        assertThat(turn.totalTokens()).isEqualTo(85);

        // The same invariants the OpenAI Adapter guarantees.
        assertThat(turn.cachedInputTokens()).isLessThanOrEqualTo(turn.inputTokens());
        assertThat(turn.reasoningTokens()).isLessThanOrEqualTo(turn.outputTokens());
        assertThat(turn.totalTokens()).isEqualTo(turn.inputTokens() + turn.outputTokens());
    }

    @Test
    void anthropicCacheCreationTokensCountAsInputButNotCachedHits() {
        String sse = """
                event: message_start
                data: {"type":"message_start","message":{"model":"claude-sonnet-4-6",\
                "usage":{"input_tokens":5,"cache_read_input_tokens":3,\
                "cache_creation_input_tokens":7,"output_tokens":1}}}

                event: message_delta
                data: {"type":"message_delta","delta":{"stop_reason":"max_tokens"},\
                "usage":{"output_tokens":2}}

                event: message_stop
                data: {"type":"message_stop"}
                """;

        NormalizedTurn turn = anthropic.finalizeTurn(
                draft(sse.getBytes(StandardCharsets.UTF_8), "claude-sonnet-4-6"));
        assertThat(turn.status()).isEqualTo("incomplete");
        assertThat(turn.inputTokens()).isEqualTo(15);
        assertThat(turn.cachedInputTokens()).isEqualTo(3);
        assertThat(turn.uncachedInputTokens()).isEqualTo(12);
        assertThat(turn.outputTokens()).isEqualTo(2);
        assertThat(turn.totalTokens()).isEqualTo(17);
    }

    @Test
    void anthropicNonStreamingJsonNormalisesWithUsageAndToolCalls() {
        String json = """
                {"id":"msg_123","type":"message","role":"assistant","model":"claude-sonnet-5",\
                "content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"toolu_1",\
                "name":"noop","input":{}}],"stop_reason":"end_turn",\
                "usage":{"input_tokens":12,"cache_read_input_tokens":4,\
                "cache_creation_input_tokens":6,"output_tokens":3}}
                """;

        NormalizedTurn turn = anthropic.finalizeTurn(
                draft(json.getBytes(StandardCharsets.UTF_8), "claude-sonnet-5"));

        assertThat(turn.servedModel()).isEqualTo("claude-sonnet-5");
        assertThat(turn.status()).isEqualTo("completed");
        assertThat(turn.inputTokens()).isEqualTo(22);
        assertThat(turn.cachedInputTokens()).isEqualTo(4);
        assertThat(turn.uncachedInputTokens()).isEqualTo(18);
        assertThat(turn.outputTokens()).isEqualTo(3);
        assertThat(turn.totalTokens()).isEqualTo(25);
        assertThat(turn.toolCalls()).isEqualTo(1);
    }

    @Test
    void anthropicSseAllowsCrLfLineEndings() {
        String sse = String.join("\r\n",
                "event: message_start",
                "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-5\","
                        + "\"usage\":{\"input_tokens\":2,\"cache_read_input_tokens\":1,"
                        + "\"cache_creation_input_tokens\":3,\"output_tokens\":0}}}",
                "",
                "event: message_delta",
                "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},"
                        + "\"usage\":{\"output_tokens\":4}}",
                "",
                "event: message_stop",
                "data: {\"type\":\"message_stop\"}",
                "");

        NormalizedTurn turn = anthropic.finalizeTurn(
                draft(sse.getBytes(StandardCharsets.UTF_8), "claude-sonnet-5"));

        assertThat(turn.status()).isEqualTo("completed");
        assertThat(turn.inputTokens()).isEqualTo(6);
        assertThat(turn.cachedInputTokens()).isEqualTo(1);
        assertThat(turn.outputTokens()).isEqualTo(4);
        assertThat(turn.totalTokens()).isEqualTo(10);
    }

    @Test
    void bothAdaptersProduceTheSameRecordShape() {
        NormalizedTurn openaiTurn = openai.finalizeTurn(
                draft(fixture("openai-responses-completed.sse"), "gpt-5-codex"));
        NormalizedTurn anthropicTurn = anthropic.finalizeTurn(
                draft(fixture("anthropic-messages-completed.sse"), "claude-sonnet-4-6"));

        // Same normalised model, different Providers — one pipeline downstream.
        assertThat(openaiTurn).isInstanceOf(NormalizedTurn.class);
        assertThat(anthropicTurn).isInstanceOf(NormalizedTurn.class);
        assertThat(openaiTurn.provider()).isNotEqualTo(anthropicTurn.provider());
        assertThat(openaiTurn.status()).isEqualTo("completed");
        assertThat(anthropicTurn.status()).isEqualTo("completed");
    }
}
