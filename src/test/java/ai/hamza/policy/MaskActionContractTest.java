package ai.hamza.policy;

import ai.hamza.config.HamzaProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MaskActionContractTest {

    private static final String FAKE_KEY = "AKIAABCDEFGHIJKLMNOP";

    @Test
    void runtimeActionsAreFlagMaskAndBlockOnly() {
        assertThat(Arrays.stream(Action.values()).map(Enum::name))
                .containsExactly("FLAG", "MASK", "BLOCK");
    }

    @Test
    void legacyRedactPostureIsRejectedAndMaskBinds() {
        assertThat(bind("MASK").policy().posture()).isEqualTo(Action.MASK);
        assertThatThrownBy(() -> bind("REDACT"))
                .isInstanceOf(BindException.class)
                .hasMessageContaining("hamza.policy");
    }

    @Test
    void blockBeatsMaskAndMaskBeatsFlag() {
        PolicyEngine mask = engine(Action.MASK, Map.of());
        assertThat(mask.evaluate(body()).effectiveAction()).isEqualTo(Action.MASK);

        PolicyEngine block = engine(Action.FLAG,
                Map.of("aws-access-token", Action.BLOCK));
        assertThat(block.evaluate(body()).effectiveAction()).isEqualTo(Action.BLOCK);
    }

    @Test
    void exactSpanSingleTurnMaskingPreservesSurroundingBody() {
        PolicyResult result = engine(Action.MASK, Map.of()).evaluate(body());
        String masked = new String(result.maskedBody().orElseThrow(), StandardCharsets.UTF_8);

        assertThat(masked).doesNotContain(FAKE_KEY);
        assertThat(masked).contains("«redacted:aws-access-token»");
        assertThat(masked).contains("\"model\":\"gpt-5-codex\"");
        assertThat(result.findings()).allMatch(finding -> finding.detector().equals("secret"));
    }

    private static PolicyEngine engine(Action posture, Map<String, Action> overrides) {
        return new PolicyEngine(new SecretDetector(), new Masker(), posture, overrides);
    }

    private static byte[] body() {
        return ("{\"model\":\"gpt-5-codex\",\"input\":\"use " + FAKE_KEY + "\"}")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static HamzaProperties bind(String posture) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("test",
                Map.of("hamza.policy.posture", posture)));
        return Binder.get(environment).bind("hamza", HamzaProperties.class)
                .orElseThrow(() -> new IllegalStateException("Hamza properties did not bind"));
    }
}
