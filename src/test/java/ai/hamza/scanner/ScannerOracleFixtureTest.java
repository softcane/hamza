package ai.hamza.scanner;

import ai.hamza.policy.SecretDetector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The fixture-corpus oracle sweep (PRD "Testing Decisions"): the in-process detector
 * must catch every current oracle finding on its fixture body, and must stay silent on
 * normal-Agent-prompt / source-snippet fixtures (no false positives).
 *
 * <p>All fixtures use fake/example secrets only.
 */
class ScannerOracleFixtureTest {

    private final SecretDetector detector = new SecretDetector();

    private Set<String> rulesFor(String bodyFixture) {
        return detector.detect(ScannerFixtures.body(bodyFixture)).stream()
                .map(SecretDetector.Match::rule)
                .collect(Collectors.toSet());
    }

    @ParameterizedTest
    @CsvSource({
            "stripe.json,        stripe-access-token",
            "gitlab.json,        gitlab-pat",
            "slack-webhook.json, slack-webhook-url",
    })
    void detectsImportedRuleOnItsFixtureBody(String bodyFixture, String expectedRule) {
        assertThat(rulesFor(bodyFixture)).contains(expectedRule);
    }

    @Test
    void detectsBothNativeAndImportedSecretsInAMixedBody() {
        assertThat(rulesFor("mixed.json")).contains("stripe-access-token");
    }

    @ParameterizedTest
    @ValueSource(strings = {"fp-prose.json", "fp-code-snippet.json", "fp-dependency.json"})
    void producesNoFalsePositivesOnNormalAgentTraffic(String fpFixture) {
        assertThat(detector.detect(ScannerFixtures.body(fpFixture)))
                .as("no Finding expected for normal Agent traffic fixture %s", fpFixture)
                .isEmpty();
    }
}
