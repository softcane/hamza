package ai.hamza.scanner;

import ai.hamza.policy.SecretDetector;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.ArrayList;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** Coverage comparison (Hamza vs the offline oracle) and duplicate-finding handling (Q18). */
class ScannerComparisonTest {

    private final SecretDetector detector = new SecretDetector();
    private final OracleReportParser parser =
            new OracleReportParser(new ObjectMapper(), new OracleRuleMapper());
    private final ScannerComparison comparison = new ScannerComparison();

    @Test
    void comparisonSurfacesOracleOnlyCoverageGap() {
        String body = ScannerFixtures.body("stripe.json");
        List<ScanFinding> hamza = comparison.fromDetector(detector.detect(body));
        List<ScanFinding> oracle = new ArrayList<>(parser.parse(ScannerFixtures.oracleReport("stripe.json")));
        oracle.add(new ScanFinding(ScannerSource.ORACLE, "oracle:generic-api-key",
                Optional.empty(), Confidence.MEDIUM));

        ScannerComparison.Comparison c = comparison.compare(hamza, oracle);

        assertThat(c.agreed()).containsExactly("stripe-access-token");
        assertThat(c.hamzaOnly()).isEmpty();
        assertThat(c.oracleOnly()).containsExactly("oracle:generic-api-key");
        assertThat(c.hasCoverageGap()).isTrue();
    }

    @Test
    void duplicateAcrossScannersCollapsesToOneRedactableFinding() {
        // Hamza and Oracle both flag the same AWS key: Hamza with a span, Oracle without.
        ScanFinding hamza = ScanFinding.hamza("aws-access-key-id", new Span(22, 42), Confidence.HIGH);
        ScanFinding oracle = new ScanFinding(ScannerSource.ORACLE, "aws-access-key-id",
                Optional.empty(), Confidence.HIGH);

        List<ScanFinding> deduped = comparison.deduplicate(List.of(oracle, hamza));

        assertThat(deduped).hasSize(1);
        assertThat(deduped.getFirst().source()).isEqualTo(ScannerSource.HAMZA);
        assertThat(deduped.getFirst().canRedact()).as("the redactable finding wins").isTrue();
    }

    @Test
    void distinctRulesAndNonOverlappingSpansAreNotDeduped() {
        ScanFinding aws = ScanFinding.hamza("aws-access-key-id", new Span(0, 20), Confidence.HIGH);
        ScanFinding stripe = ScanFinding.hamza("stripe-access-token", new Span(30, 62), Confidence.HIGH);
        // Two different occurrences of the same rule (non-overlapping) are two leaks.
        ScanFinding awsTwo = ScanFinding.hamza("aws-access-key-id", new Span(80, 100), Confidence.HIGH);

        assertThat(comparison.deduplicate(List.of(aws, stripe, awsTwo))).hasSize(3);
    }

    @Test
    void detectorAndOracleAgreeOnImportedRule() {
        // The imported stripe rule: Hamza now detects what the oracle reported.
        String body = ScannerFixtures.body("stripe.json");
        List<ScanFinding> hamza = comparison.fromDetector(detector.detect(body));
        List<ScanFinding> oracle = parser.parse(ScannerFixtures.oracleReport("stripe.json"));

        ScannerComparison.Comparison c = comparison.compare(hamza, oracle);
        assertThat(c.agreed()).containsExactly("stripe-access-token");
        assertThat(c.oracleOnly()).isEmpty();
    }
}
