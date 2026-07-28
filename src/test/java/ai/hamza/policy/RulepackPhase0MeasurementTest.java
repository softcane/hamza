package ai.hamza.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Manual Phase-0 measurement. Run with:
 * {@code mvn -Dhamza.rulepack.measure=true -Dtest=RulepackPhase0MeasurementTest test}.
 */
@Tag("rulepack-benchmark")
class RulepackPhase0MeasurementTest {

    private final SecretDetector detector = new SecretDetector();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void measureCurrentDetectorCoverageAndFixtureLatency() throws Exception {
        assumeTrue(Boolean.getBoolean("hamza.rulepack.measure"));

        Coverage coverage = measureCoverage(Path.of("src/test/resources/scanner/rulepack-corpus"));
        Latency latency = measureLatency(Path.of("src/test/resources/scanner/bodies"), 400, 40);

        System.out.printf("RULEPACK_BASELINE_COVERAGE corpus_rules=%d tp_samples=%d " +
                        "tp_samples_with_hamza_finding=%d fp_samples=%d fp_samples_with_hamza_finding=%d " +
                        "upstream_rule_ids_with_any_hamza_finding=%d hamza_rules_seen=%s%n",
                coverage.corpusRules, coverage.tpSamples, coverage.tpCaught, coverage.fpSamples,
                coverage.fpCaught, coverage.upstreamRulesWithAnyHamzaFinding, coverage.hamzaRulesSeen);
        System.out.printf("RULEPACK_BASELINE_LATENCY fixture_bodies=%d warmup_iterations=%d " +
                        "measured_iterations=%d total_scans=%d p50_micros=%d p95_micros=%d max_micros=%d%n",
                latency.fixtureBodies, latency.warmups, latency.iterations, latency.totalScans,
                latency.p50Micros, latency.p95Micros, latency.maxMicros);
    }

    private Coverage measureCoverage(Path corpusDir) throws IOException {
        int corpusRules = 0;
        int tpSamples = 0;
        int tpCaught = 0;
        int fpSamples = 0;
        int fpCaught = 0;
        int upstreamRulesWithAnyHamzaFinding = 0;
        Set<String> hamzaRulesSeen = new TreeSet<>();

        try (Stream<Path> files = Files.list(corpusDir)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".json")).sorted().toList()) {
                corpusRules++;
                boolean anyHamzaFindingForRule = false;
                JsonNode root = objectMapper.readTree(Files.readString(file));
                List<String> truePositives = samples(root, "truePositives");
                truePositives.addAll(mapSamples(root, "pathTruePositives"));
                for (String sample : truePositives) {
                    tpSamples++;
                    List<SecretDetector.Match> matches = detector.detect(sample);
                    if (!matches.isEmpty()) {
                        tpCaught++;
                        anyHamzaFindingForRule = true;
                        matches.stream().map(SecretDetector.Match::rule).forEach(hamzaRulesSeen::add);
                    }
                }
                List<String> falsePositives = samples(root, "falsePositives");
                falsePositives.addAll(mapSamples(root, "pathFalsePositives"));
                for (String sample : falsePositives) {
                    fpSamples++;
                    List<SecretDetector.Match> matches = detector.detect(sample);
                    if (!matches.isEmpty()) {
                        fpCaught++;
                        matches.stream().map(SecretDetector.Match::rule).forEach(hamzaRulesSeen::add);
                    }
                }
                if (anyHamzaFindingForRule) {
                    upstreamRulesWithAnyHamzaFinding++;
                }
            }
        }
        return new Coverage(corpusRules, tpSamples, tpCaught, fpSamples, fpCaught,
                upstreamRulesWithAnyHamzaFinding, hamzaRulesSeen);
    }

    private Latency measureLatency(Path bodiesDir, int iterations, int warmups) throws IOException {
        List<String> bodies;
        try (Stream<Path> files = Files.list(bodiesDir)) {
            bodies = files.filter(p -> p.toString().endsWith(".json"))
                    .sorted()
                    .map(RulepackPhase0MeasurementTest::readString)
                    .toList();
        }
        for (int i = 0; i < warmups; i++) {
            for (String body : bodies) {
                detector.detect(body);
            }
        }
        List<Long> micros = new ArrayList<>(bodies.size() * iterations);
        for (int i = 0; i < iterations; i++) {
            for (String body : bodies) {
                long start = System.nanoTime();
                detector.detect(body);
                micros.add((System.nanoTime() - start) / 1_000);
            }
        }
        Collections.sort(micros);
        return new Latency(bodies.size(), warmups, iterations, micros.size(),
                percentile(micros, 0.50), percentile(micros, 0.95), micros.getLast());
    }

    private static List<String> samples(JsonNode root, String field) {
        List<String> out = new ArrayList<>();
        JsonNode array = root.get(field);
        if (array == null || !array.isArray()) {
            return out;
        }
        for (JsonNode node : array) {
            out.add(node.asText());
        }
        return out;
    }

    private static List<String> mapSamples(JsonNode root, String field) {
        JsonNode node = root.get(field);
        if (node == null || !node.isObject()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        node.properties().forEach(e -> out.add(e.getValue().asText()));
        return out;
    }

    private static long percentile(List<Long> values, double p) {
        int index = (int) Math.ceil(values.size() * p) - 1;
        return values.get(Math.max(0, Math.min(index, values.size() - 1)));
    }

    private static String readString(Path path) {
        try {
            return Files.readString(path);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private record Coverage(int corpusRules, int tpSamples, int tpCaught, int fpSamples, int fpCaught,
                            int upstreamRulesWithAnyHamzaFinding, Set<String> hamzaRulesSeen) {
    }

    private record Latency(int fixtureBodies, int warmups, int iterations, int totalScans,
                           long p50Micros, long p95Micros, long maxMicros) {
    }
}
