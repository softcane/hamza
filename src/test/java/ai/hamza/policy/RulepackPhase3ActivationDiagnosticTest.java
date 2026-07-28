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
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Manual diagnostic + latency benchmark for the Phase 3 Rulepack activation. Prints
 * corpus parity and scan-latency numbers; asserts that the only same-rule true-positive
 * misses are the six rules deferred in Phase 3 (plus the path-only pkcs12-file), and that
 * no active rule produces a same-rule false positive. Run with
 * {@code -Dhamza.rulepack.full=true}.
 */
@Tag("rulepack-benchmark")
class RulepackPhase3ActivationDiagnosticTest {

    private static final Map<String, Integer> EXPECTED_PHASE3_MISSES = Map.ofEntries(
            Map.entry("curl-auth-header", 18),
            Map.entry("curl-auth-user", 11),
            Map.entry("freemius-secret-key", 1),
            Map.entry("generic-api-key", 63),
            Map.entry("hashicorp-tf-password", 2),
            Map.entry("nuget-config-password", 6),
            Map.entry("pkcs12-file", 3)
    );

    private final SecretDetector detector = new SecretDetector();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void measureFullRulepackCorpusParityAndLatency() throws Exception {
        assumeTrue(Boolean.getBoolean("hamza.rulepack.full"));

        CorpusResult corpus = measureCorpus(Path.of("src/test/resources/scanner/rulepack-corpus"));
        Latency latency = measureLatency(Path.of("src/test/resources/scanner/bodies"), 200, 20);

        System.out.printf("RULEPACK_PHASE2_CORPUS rules=%d active_rules=%d rules_with_tp=%d " +
                        "rules_with_all_tp_same_rule=%d tp_samples=%d tp_same_rule=%d tp_any_rule=%d " +
                        "fp_samples=%d fp_same_rule=%d fp_any_rule=%d same_rule_miss_rules=%d%n",
                corpus.rules, corpus.activeRules, corpus.rulesWithTruePositiveSamples,
                corpus.rulesWithAllTruePositivesSameRule, corpus.truePositiveSamples,
                corpus.truePositivesSameRule, corpus.truePositivesAnyRule, corpus.falsePositiveSamples,
                corpus.falsePositivesSameRule, corpus.falsePositivesAnyRule, corpus.sameRuleMisses.size());
        System.out.printf("RULEPACK_PHASE2_LATENCY fixture_bodies=%d warmup_iterations=%d " +
                        "measured_iterations=%d total_scans=%d p50_micros=%d p95_micros=%d max_micros=%d%n",
                latency.fixtureBodies, latency.warmups, latency.iterations, latency.totalScans,
                latency.p50Micros, latency.p95Micros, latency.maxMicros);
        System.out.printf("RULEPACK_PHASE2_MISSES %s%n", summarize(corpus.sameRuleMisses, 40));
        System.out.printf("RULEPACK_PHASE2_FP_SAME_RULE %s%n", summarize(corpus.sameRuleFalsePositives, 40));

        assertThat(corpus.sameRuleFalsePositives).as("same-rule false positives").isEmpty();
        assertThat(corpus.sameRuleMisses).as("only documented Phase 3 exclusions may miss")
                .containsExactlyInAnyOrderEntriesOf(EXPECTED_PHASE3_MISSES);
    }

    private CorpusResult measureCorpus(Path corpusDir) throws IOException {
        int rules = 0;
        int activeRules = RulepackLoader.loadDefault().ruleCount();
        int rulesWithTruePositiveSamples = 0;
        int rulesWithAllTruePositivesSameRule = 0;
        int truePositiveSamples = 0;
        int truePositivesSameRule = 0;
        int truePositivesAnyRule = 0;
        int falsePositiveSamples = 0;
        int falsePositivesSameRule = 0;
        int falsePositivesAnyRule = 0;
        Map<String, Integer> sameRuleMisses = new TreeMap<>();
        Map<String, Integer> sameRuleFalsePositives = new TreeMap<>();

        try (Stream<Path> files = Files.list(corpusDir)) {
            for (Path file : files.filter(p -> p.toString().endsWith(".json")).sorted().toList()) {
                rules++;
                JsonNode root = objectMapper.readTree(Files.readString(file));
                String ruleId = root.get("ruleId").asText();
                List<String> truePositives = samples(root, "truePositives");
                truePositives.addAll(mapSamples(root, "pathTruePositives"));
                if (!truePositives.isEmpty()) {
                    rulesWithTruePositiveSamples++;
                }
                int ruleTp = 0;
                int ruleSame = 0;
                for (String sample : truePositives) {
                    truePositiveSamples++;
                    ruleTp++;
                    List<SecretDetector.Match> matches = detector.detect(sample);
                    if (!matches.isEmpty()) {
                        truePositivesAnyRule++;
                    }
                    if (matches.stream().anyMatch(match -> match.rule().equals(ruleId))) {
                        truePositivesSameRule++;
                        ruleSame++;
                    } else {
                        sameRuleMisses.merge(ruleId, 1, Integer::sum);
                    }
                }
                if (ruleTp > 0 && ruleTp == ruleSame) {
                    rulesWithAllTruePositivesSameRule++;
                }

                List<String> falsePositives = samples(root, "falsePositives");
                falsePositives.addAll(mapSamples(root, "pathFalsePositives"));
                for (String sample : falsePositives) {
                    falsePositiveSamples++;
                    List<SecretDetector.Match> matches = detector.detect(sample);
                    if (!matches.isEmpty()) {
                        falsePositivesAnyRule++;
                    }
                    if (matches.stream().anyMatch(match -> match.rule().equals(ruleId))) {
                        falsePositivesSameRule++;
                        sameRuleFalsePositives.merge(ruleId, 1, Integer::sum);
                    }
                }
            }
        }
        return new CorpusResult(rules, activeRules, rulesWithTruePositiveSamples,
                rulesWithAllTruePositivesSameRule, truePositiveSamples, truePositivesSameRule,
                truePositivesAnyRule, falsePositiveSamples, falsePositivesSameRule,
                falsePositivesAnyRule, sameRuleMisses, sameRuleFalsePositives);
    }

    private Latency measureLatency(Path bodiesDir, int iterations, int warmups) throws IOException {
        List<String> bodies;
        try (Stream<Path> files = Files.list(bodiesDir)) {
            bodies = files.filter(p -> p.toString().endsWith(".json"))
                    .sorted()
                    .map(RulepackPhase3ActivationDiagnosticTest::readString)
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

    private static String summarize(Map<String, Integer> counts, int limit) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(limit)
                .map(e -> e.getKey() + "=" + e.getValue())
                .toList()
                .toString();
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

    private record CorpusResult(int rules,
                                int activeRules,
                                int rulesWithTruePositiveSamples,
                                int rulesWithAllTruePositivesSameRule,
                                int truePositiveSamples,
                                int truePositivesSameRule,
                                int truePositivesAnyRule,
                                int falsePositiveSamples,
                                int falsePositivesSameRule,
                                int falsePositivesAnyRule,
                                Map<String, Integer> sameRuleMisses,
                                Map<String, Integer> sameRuleFalsePositives) {
    }

    private record Latency(int fixtureBodies,
                           int warmups,
                           int iterations,
                           int totalScans,
                           long p50Micros,
                           long p95Micros,
                           long maxMicros) {
    }
}
