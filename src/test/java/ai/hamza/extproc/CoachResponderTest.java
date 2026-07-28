package ai.hamza.extproc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.envoyproxy.envoy.service.ext_proc.v3.ImmediateResponse;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingResponse;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Coach body behaviour: a Block presents as a valid per-Provider wire-format
 * body that names the rule class only, never the matched content, and forbids retry /
 * re-encoding. Disabled Coach falls back to the byte-for-byte bare 403.
 */
class CoachResponderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static String body(ProcessingResponse resp) {
        ImmediateResponse ir = resp.getImmediateResponse();
        return ir.getBody().toStringUtf8();
    }

    private static int status(ProcessingResponse resp) {
        return resp.getImmediateResponse().getStatus().getCode().getNumber();
    }

    @Test
    void disabledCoachEmitsBareText403() {
        CoachResponder coach = CoachResponder.disabled();
        ProcessingResponse resp = coach.blockResponse("openai", List.of("edm-customers"));
        assertThat(status(resp)).isEqualTo(403);
        assertThat(body(resp)).isEqualTo("Blocked by Hamza: edm-customers\n");
    }

    @Test
    void openAiCoachIsValidErrorEnvelopeNamingRuleClassOnly() throws Exception {
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        ProcessingResponse resp = coach.blockResponse("openai", List.of("edm-customers"));
        assertThat(status(resp)).isEqualTo(403);

        JsonNode root = MAPPER.readTree(body(resp).getBytes(StandardCharsets.UTF_8));
        JsonNode error = root.path("error");
        assertThat(error.path("type").asText()).isEqualTo("egress_withheld");
        String message = error.path("message").asText();
        // Names the rule class, forbids retry/re-encode, proposes a compliant path.
        assertThat(message).contains("edm-customers");
        assertThat(message).containsIgnoringCase("do not retry");
        assertThat(message).containsIgnoringCase("re-encode");
        assertThat(message).containsIgnoringCase("synthetic");
    }

    @Test
    void anthropicCoachIsValidErrorEnvelope() throws Exception {
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        ProcessingResponse resp = coach.blockResponse("anthropic", List.of("edm-customers"));

        JsonNode root = MAPPER.readTree(body(resp).getBytes(StandardCharsets.UTF_8));
        assertThat(root.path("type").asText()).isEqualTo("error");
        assertThat(root.path("error").path("type").asText()).isEqualTo("permission_error");
        assertThat(root.path("error").path("message").asText()).contains("edm-customers");
    }

    @Test
    void coachBodyNeverCarriesMatchedContent() {
        // Rule-class names are the only inputs; a matched value can never appear in the body.
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        String openai = body(coach.blockResponse("openai", List.of("edm-customers")));
        String anthropic = body(coach.blockResponse("anthropic", List.of("aws-access-token")));
        assertThat(openai).doesNotContain("@example-corp.test");
        assertThat(openai).doesNotContain("AKIA");
        assertThat(anthropic).doesNotContain("@example-corp.test");
        assertThat(anthropic).doesNotContain("AKIA");
    }

    @Test
    void unknownProviderFallsBackToBareText() {
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        ProcessingResponse resp = coach.blockResponse(null, List.of("edm-customers"));
        assertThat(status(resp)).isEqualTo(403);
        assertThat(body(resp)).isEqualTo("Blocked by Hamza: edm-customers\n");
    }

    @Test
    void statusIsConfigurable() {
        CoachResponder coach = new CoachResponder(true, 200, Map.of());
        assertThat(status(coach.blockResponse("openai", List.of("edm-customers")))).isEqualTo(200);
    }

    @Test
    void templateOverrideIsHonoured() {
        CoachResponder coach = new CoachResponder(true, 403,
                Map.of("openai", "Withheld by policy: {rules}. Ask a human."));
        String body = body(coach.blockResponse("openai", List.of("edm-customers")));
        assertThat(body).contains("Withheld by policy: edm-customers. Ask a human.");
    }
}
