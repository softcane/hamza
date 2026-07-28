package ai.hamza.policy;

import ai.hamza.config.HamzaProperties;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.edm.EdmTurnAccumulator;
import ai.hamza.edm.RegistryStore;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * EDM policy semantics: a registry's configured BLOCK
 * fires only at the distinct-match threshold; below it, matches FLAG; EDM never
 * masks; the streamed/prefix path enforces the same way.
 */
class PolicyEngineEdmTest {

    private static final int THRESHOLD = 10;

    private PolicyEngine engine(Action posture, Map<String, Action> ruleActions) throws Exception {
        Path dir = Path.of(getClass().getResource("/edm").toURI());
        EdmMatcher matcher = new EdmMatcher(new RegistryStore(
                new HamzaProperties(null, null,
                        new HamzaProperties.Edm(dir.toString(), THRESHOLD, true, null))));
        return new PolicyEngine(new SecretDetector(), new Masker(), posture, ruleActions,
                matcher, THRESHOLD);
    }

    private static byte[] dumpWithEmails(int n) {
        return dumpWithEmails(1, n);
    }

    private static byte[] dumpWithEmails(int from, int to) {
        StringBuilder sb = new StringBuilder("{\"rows\": [");
        for (int i = from; i <= to; i++) {
            sb.append("{\"email\": \"fake%03d@example-corp.test\"},".formatted(i));
        }
        return sb.append("]}").toString().getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void dumpAtThresholdBlocksWhenRegistryRuleIsBlock() throws Exception {
        PolicyEngine engine = engine(Action.FLAG, Map.of("edm-customers", Action.BLOCK));
        PolicyResult result = engine.evaluate(dumpWithEmails(12));
        assertThat(result.isBlock()).isTrue();
        assertThat(result.blockingRules()).containsExactly("edm-customers");
        assertThat(result.findings()).anyMatch(
                f -> f.rule().equals("edm-customers") && f.action() == Action.BLOCK);
    }

    @Test
    void fewMatchesOnlyFlagEvenWhenRuleIsBlock() throws Exception {
        PolicyEngine engine = engine(Action.FLAG, Map.of("edm-customers", Action.BLOCK));
        PolicyResult result = engine.evaluate(dumpWithEmails(3));
        assertThat(result.isBlock()).isFalse();
        assertThat(result.effectiveAction()).isEqualTo(Action.FLAG);
        assertThat(result.findings()).anyMatch(
                f -> f.rule().equals("edm-customers") && f.action() == Action.FLAG);
    }

    @Test
    void edmNeverMasksUnderMaskPosture() throws Exception {
        // MASK posture: EDM has no reliable spans, so it clamps to FLAG — the body
        // must pass unmutated (no maskedBody present).
        PolicyEngine engine = engine(Action.MASK, Map.of());
        PolicyResult result = engine.evaluate(dumpWithEmails(12));
        assertThat(result.isBlock()).isFalse();
        assertThat(result.maskedBody()).isEmpty();
        assertThat(result.findings()).anyMatch(
                f -> f.rule().equals("edm-customers") && f.action() == Action.FLAG);
    }

    @Test
    void prefixPathEnforcesTheSameThreshold() throws Exception {
        PolicyEngine engine = engine(Action.FLAG, Map.of("edm-customers", Action.BLOCK));
        PolicyResult result = engine.evaluatePrefix(dumpWithEmails(12));
        assertThat(result.isBlock()).isTrue();
        assertThat(result.blockingRules()).containsExactly("edm-customers");
    }

    @Test
    void streamedChunksAccumulateDistinctMatchesAcrossTheTurn() throws Exception {
        // 6 emails per chunk: each window is below the threshold of 10, but the Turn's
        // running total (12 distinct) must block on the second chunk.
        PolicyEngine engine = engine(Action.FLAG, Map.of("edm-customers", Action.BLOCK));
        EdmTurnAccumulator acc = new EdmTurnAccumulator();

        PolicyResult first = engine.evaluateStreamChunk(dumpWithEmails(1, 6), acc);
        assertThat(first.isBlock()).isFalse();
        assertThat(first.findings()).anyMatch(
                f -> f.rule().equals("edm-customers") && f.action() == Action.FLAG);

        PolicyResult second = engine.evaluateStreamChunk(dumpWithEmails(7, 12), acc);
        assertThat(second.isBlock()).isTrue();
        assertThat(second.blockingRules()).containsExactly("edm-customers");
    }

    @Test
    void repeatedValuesAcrossChunksDoNotInflateTheTurnCount() throws Exception {
        // The SAME 6 emails in every chunk stay 6 distinct — repetition is not a dump.
        PolicyEngine engine = engine(Action.FLAG, Map.of("edm-customers", Action.BLOCK));
        EdmTurnAccumulator acc = new EdmTurnAccumulator();
        engine.evaluateStreamChunk(dumpWithEmails(1, 6), acc);
        PolicyResult again = engine.evaluateStreamChunk(dumpWithEmails(1, 6), acc);
        assertThat(again.isBlock()).isFalse();
    }

    @Test
    void engineWithoutMatcherIsUnchanged() {
        PolicyEngine engine = new PolicyEngine(new SecretDetector(), new Masker(),
                Action.FLAG, Map.of());
        PolicyResult result = engine.evaluate(dumpWithEmails(12));
        assertThat(result.findings()).isEmpty();
        assertThat(result.effectiveAction()).isEqualTo(Action.FLAG);
    }
}
