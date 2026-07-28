package ai.hamza.scanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Parsing the offline Oracle JSON oracle into normalised, content-free findings.
 * Crucially: the raw {@code Match}/{@code Secret} values in the report are discarded —
 * they never reach the {@link ScanFinding} model.
 */
class OracleReportParserTest {

    // The fake secret values embedded in the checked-in reports; none may survive parsing.
    private static final List<String> FAKE_SECRETS = List.of(
            "AKIAIOSFODNN7EXAMPLE",
            "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
            "glpat-ABCDEFGHIJKLMNOP1234",
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");

    private final OracleReportParser parser =
            new OracleReportParser(new ObjectMapper(), new OracleRuleMapper());

    @Test
    void parsesReportAndNormalisesRuleIds() {
        List<ScanFinding> findings = parser.parse(ScannerFixtures.oracleReport("mixed.json"));

        assertThat(findings).extracting(ScanFinding::ruleId)
                .containsExactly("stripe-access-token");
        assertThat(findings).allMatch(f -> f.source() == ScannerSource.ORACLE);
    }

    @Test
    void discardsRawSecretValues() {
        // Parse every checked-in report and prove no fake secret string leaks into the model.
        for (String report : List.of("stripe.json", "mixed.json", "gitlab.json", "slack-webhook.json")) {
            List<ScanFinding> findings = parser.parse(ScannerFixtures.oracleReport(report));
            for (ScanFinding f : findings) {
                for (String secret : FAKE_SECRETS) {
                    assertThat(f.toString())
                            .as("finding must not carry the raw secret from %s", report)
                            .doesNotContain(secret);
                }
                // The model has no span field populated from the CLI report -> Flag/Block only.
                assertThat(f.span()).isEmpty();
                assertThat(f.canRedact()).isFalse();
            }
        }
    }

    @Test
    void oracleOnlyRulesAreFlagBlockOnly() {
        String rawReport = """
                [{"RuleID":"generic-api-key","Match":"api_key = fake-not-real","Secret":"fake-not-real"}]
                """;
        ScanFinding generic = parser.parse(rawReport).stream()
                .filter(f -> f.ruleId().startsWith("oracle:"))
                .findFirst().orElseThrow();
        assertThat(generic.canRedact()).isFalse();
        assertThat(generic.confidence()).isEqualTo(Confidence.MEDIUM);
    }

    @Test
    void cleanReportYieldsNoFindings() {
        assertThat(parser.parse(ScannerFixtures.oracleReport("fp-prose.json"))).isEmpty();
        assertThat(parser.parse("")).isEmpty();
        assertThat(parser.parse((String) null)).isEmpty();
    }

    @Test
    void malformedReportThrowsRatherThanTrustingPartialData() {
        assertThatThrownBy(() -> parser.parse("{not json"))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void nonArrayReportYieldsNoFindings() {
        assertThat(parser.parse("{\"RuleID\":\"aws-access-token\"}")).isEmpty();
    }
}
