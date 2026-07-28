package ai.hamza.masking;

import ai.hamza.adapter.AnthropicMessagesAdapter;
import ai.hamza.adapter.ContentSegment;
import ai.hamza.adapter.ContinuationExtraction;
import ai.hamza.adapter.ContinuationTransformation;
import ai.hamza.adapter.ContinuationView;
import ai.hamza.adapter.OpenAiResponsesAdapter;
import ai.hamza.adapter.ProviderAdapter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AdapterMaskingContractTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void openAiReserializesMessagesAndFunctionArgumentsWithoutChangingMetadata()
            throws Exception {
        byte[] source = ("{\"model\":\"gpt-5-codex\",\"instructions\":\"keep this\","
                + "\"input\":[{\"type\":\"message\",\"role\":\"user\","
                + "\"content\":[{\"type\":\"input_text\",\"text\":\"use "
                + MaskingTestFixture.SECRET + "\"}]},{\"type\":\"function_call\","
                + "\"name\":\"lookup\",\"call_id\":\"call-1\",\"arguments\":"
                + "\"{\\\"key\\\":\\\"" + MaskingTestFixture.SECRET
                + "\\\"}\"}]}" ).getBytes(StandardCharsets.UTF_8);

        JsonNode derived = transform(new OpenAiResponsesAdapter(), source);

        assertThat(derived.path("model").asText()).isEqualTo("gpt-5-codex");
        assertThat(derived.path("instructions").asText()).isEqualTo("keep this");
        assertThat(derived.toString()).doesNotContain(MaskingTestFixture.SECRET);
        assertThat(derived.toString().split("<SECRET_", -1)).hasSize(3);
    }

    @Test
    void anthropicReserializesTextAndNestedToolArgumentsWithoutChangingMetadata()
            throws Exception {
        byte[] source = ("{\"model\":\"claude-haiku-4-5-20251001\",\"max_tokens\":256,"
                + "\"system\":\"keep this\",\"messages\":[{\"role\":\"user\","
                + "\"content\":\"use " + MaskingTestFixture.SECRET + "\"},{\"role\":"
                + "\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"tool-1\","
                + "\"name\":\"lookup\",\"input\":{\"nested\":{\"key\":\""
                + MaskingTestFixture.SECRET + "\"}}}]}]}" ).getBytes(StandardCharsets.UTF_8);

        JsonNode derived = transform(new AnthropicMessagesAdapter(), source);

        assertThat(derived.path("model").asText()).isEqualTo("claude-haiku-4-5-20251001");
        assertThat(derived.path("max_tokens").asInt()).isEqualTo(256);
        assertThat(derived.path("system").asText()).isEqualTo("keep this");
        assertThat(derived.toString()).doesNotContain(MaskingTestFixture.SECRET);
        assertThat(derived.toString().split("<SECRET_", -1)).hasSize(3);
    }

    private static JsonNode transform(ProviderAdapter adapter, byte[] source) throws Exception {
        ContinuationExtraction.Valid extracted =
                (ContinuationExtraction.Valid) adapter.extractContinuation(source);
        ContinuationView view = extracted.view();
        List<MaskCandidate> candidates = new ArrayList<>();
        for (ContentSegment segment : view.segments()) {
            int from = 0;
            while ((from = segment.text().indexOf(MaskingTestFixture.SECRET, from)) >= 0) {
                int end = from + MaskingTestFixture.SECRET.length();
                candidates.add(new MaskCandidate("secret", "aws-access-token",
                        PlaceholderFamily.SECRET, segment.id(),
                        segment.text().codePointCount(0, from),
                        segment.text().codePointCount(0, end)));
                from = end;
            }
        }
        MaskPlan plan = new MaskPlanner(new MaskScopeStore())
                .plan("scope-1", view.segments(), candidates);
        ContinuationTransformation.Success transformed =
                (ContinuationTransformation.Success) adapter.transformContinuation(
                        view, plan.edits(), "");
        return JSON.readTree(transformed.body());
    }
}
