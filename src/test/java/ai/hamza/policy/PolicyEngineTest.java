package ai.hamza.policy;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Policy decisions: Flag (default Posture), Mask, Block, and framing integrity. */
class PolicyEngineTest {

    private static final String AWS_KEY = "AKIAABCDEFGHIJKLMNOP";
    private static final String GITHUB_PAT = "ghp_9xs703a3j1eqgf9uzht09b3opv765kzeio23";
    private final SecretDetector detector = new SecretDetector();
    private final Masker masker = new Masker();

    private PolicyEngine engine(Action posture, Map<String, Action> overrides) {
        return new PolicyEngine(detector, masker, posture, overrides);
    }

    private byte[] bodyWithKey() {
        return ("{\"model\":\"gpt-5-codex\",\"input\":\"deploy with " + AWS_KEY + "\"}")
                .getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void defaultPostureFlagsWithoutMutatingOrBlocking() {
        PolicyResult r = engine(Action.FLAG, Map.of()).evaluate(bodyWithKey());
        assertThat(r.hasFindings()).isTrue();
        assertThat(r.findings()).extracting(Finding::rule).contains("aws-access-token");
        assertThat(r.effectiveAction()).isEqualTo(Action.FLAG);
        assertThat(r.isBlock()).isFalse();
        assertThat(r.isMask()).isFalse();
        assertThat(r.maskedBody()).isEmpty();
    }

    @Test
    void blockPostureStopsTheRequest() {
        PolicyResult r = engine(Action.FLAG, Map.of("aws-access-token", Action.BLOCK)).evaluate(bodyWithKey());
        assertThat(r.isBlock()).isTrue();
        assertThat(r.blockingRules()).contains("aws-access-token");
        assertThat(r.maskedBody()).isEmpty(); // block wins, no masking
    }

    @Test
    void maskPostureRemovesTheSecretAndKeepsFraming() {
        PolicyResult r = engine(Action.MASK, Map.of()).evaluate(bodyWithKey());
        assertThat(r.isMask()).isTrue();
        byte[] masked = r.maskedBody().orElseThrow();
        String maskedText = new String(masked, StandardCharsets.UTF_8);

        // The secret value is gone; a content-free placeholder is in its place.
        assertThat(maskedText).doesNotContain(AWS_KEY);
        assertThat(maskedText).contains("«redacted:aws-access-token»");
        // Surrounding structure is preserved.
        assertThat(maskedText).contains("\"model\":\"gpt-5-codex\"");
        // Length changed -> caller must fix Content-Length (asserted at the gate level).
        assertThat(masked.length).isNotEqualTo(bodyWithKey().length);
    }

    @Test
    void blockBeatsMaskWhenBothApply() {
        // Two secrets: one MASK, one BLOCK -> the Turn is Blocked.
        String body = "aws " + AWS_KEY + " and " + GITHUB_PAT;
        PolicyResult r = engine(Action.FLAG, Map.of(
                "aws-access-token", Action.MASK,
                "github-pat", Action.BLOCK)).evaluate(body.getBytes(StandardCharsets.UTF_8));
        assertThat(r.effectiveAction()).isEqualTo(Action.BLOCK);
        assertThat(r.isBlock()).isTrue();
    }

    @Test
    void cleanBodyProducesNoFindings() {
        PolicyResult r = engine(Action.BLOCK, Map.of()).evaluate(
                "{\"model\":\"gpt-5-codex\",\"input\":\"hello\"}".getBytes(StandardCharsets.UTF_8));
        assertThat(r.hasFindings()).isFalse();
        assertThat(r.isBlock()).isFalse();
        assertThat(r.effectiveAction()).isEqualTo(Action.FLAG);
    }

    @Test
    void oversizeCanOnlyFlagOrBlock() {
        assertThat(engine(Action.FLAG, Map.of()).oversizeAction()).isEqualTo(Action.FLAG);
        assertThat(engine(Action.MASK, Map.of()).oversizeAction()).isEqualTo(Action.FLAG);
        assertThat(engine(Action.BLOCK, Map.of()).oversizeAction()).isEqualTo(Action.BLOCK);
        assertThat(engine(Action.FLAG, Map.of("oversize", Action.BLOCK)).oversizeAction()).isEqualTo(Action.BLOCK);
    }

    @Test
    void evaluatePrefixDowngradesMaskToFlagButKeepsBlock() {
        // A partial/oversize prefix cannot be masked: a MASK rule collapses to FLAG.
        PolicyResult maskPosture = engine(Action.MASK, Map.of()).evaluatePrefix(bodyWithKey());
        assertThat(maskPosture.effectiveAction()).isEqualTo(Action.FLAG);
        assertThat(maskPosture.findings()).extracting(Finding::rule).contains("aws-access-token");
        assertThat(maskPosture.findings()).extracting(Finding::action).containsOnly(Action.FLAG);
        assertThat(maskPosture.maskedBody()).isEmpty();

        // BLOCK still wins on a prefix (block cannot be downgraded).
        PolicyResult blockRule = engine(Action.FLAG, Map.of("aws-access-token", Action.BLOCK))
                .evaluatePrefix(bodyWithKey());
        assertThat(blockRule.isBlock()).isTrue();
        assertThat(blockRule.blockingRules()).contains("aws-access-token");
    }

    @Test
    void evaluatePrefixIsCleanWhenNoSecretInPrefix() {
        PolicyResult r = engine(Action.BLOCK, Map.of())
                .evaluatePrefix("{\"model\":\"gpt-5-codex\",\"input\":\"hello".getBytes(StandardCharsets.UTF_8));
        assertThat(r.hasFindings()).isFalse();
        assertThat(r.effectiveAction()).isEqualTo(Action.FLAG);
    }

    @Test
    void decodedFindingNeverDrivesMaskingEvenWhenRuleIsConfiguredToMask() {
        String encoded = Base64.getEncoder()
                .encodeToString(("access_key_id=" + AWS_KEY).getBytes(StandardCharsets.UTF_8));
        byte[] body = ("{\"blob\":\"" + encoded + "\"}").getBytes(StandardCharsets.UTF_8);

        PolicyResult r = engine(Action.FLAG, Map.of("aws-access-token", Action.MASK)).evaluate(body);

        assertThat(r.effectiveAction()).isEqualTo(Action.FLAG);
        assertThat(r.maskedBody()).isEmpty();
        assertThat(r.findings())
                .filteredOn(f -> f.rule().equals("aws-access-token"))
                .extracting(Finding::action)
                .containsOnly(Action.FLAG);
    }
}
