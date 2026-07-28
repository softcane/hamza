package ai.hamza.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * Phase 3 acceptance gate for the Rulepack. Proves, against the checked-in upstream
 * parity corpus, that:
 *
 * <ul>
 *   <li>every <strong>active</strong> rule catches every one of its upstream true-positive
 *       samples (no false negatives among activated rules);</li>
 *   <li>no active rule fires on any upstream false-positive sample (zero same-rule false
 *       positives);</li>
 *   <li>the three benign fixture bodies stay completely clean (the Phase 3 FP budget);</li>
 *   <li>the base64/URL decode-and-rescan loop finds a secret one and several levels deep
 *       and stays bounded on pathological nesting.</li>
 * </ul>
 *
 * <p>The six rules deliberately deferred in Phase 3 ({@link #DEFERRED}) are documented in
 * {@code docs/adr/0016}; this test asserts they are inactive and therefore excused from the
 * true-positive requirement.
 */
class RulepackPhase3ParityTest {

    /** Deferred in Phase 3 (see docs/adr/0016); excused from the true-positive requirement. */
    private static final Set<String> DEFERRED = Set.of(
            "generic-api-key", "curl-auth-header", "curl-auth-user",
            "freemius-secret-key", "hashicorp-tf-password", "nuget-config-password",
            "pkcs12-file");

    private static final Set<String> FALSE_POSITIVE_DEFERRED = Set.of(
            "curl-auth-header", "curl-auth-user",
            "freemius-secret-key", "hashicorp-tf-password", "nuget-config-password");

    private final SecretDetector detector = new SecretDetector();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void activationShapeMatchesPhase3() {
        RulepackExecutor executor = RulepackLoader.loadDefault();
        assertThat(executor.ruleCount()).isEqualTo(327);
        assertThat(executor.ruleIds()).contains(
                "jwt", "jwt-base64", "private-key", "kubernetes-secret-yaml",
                "high-entropy-assignment", "aws-access-token", "stripe-access-token");
        assertThat(executor.ruleIds()).doesNotContain(DEFERRED.toArray(new String[0]));
    }

    @Test
    void activeRulesCatchEveryTruePositiveWithZeroSameRuleFalsePositives() throws IOException {
        Set<String> active = Set.copyOf(RulepackLoader.loadDefault().ruleIds());
        Map<String, Integer> activeFalseNegatives = new TreeMap<>();
        Map<String, Integer> sameRuleFalsePositives = new TreeMap<>();

        try (Stream<Path> files = Files.list(Path.of("src/test/resources/scanner/rulepack-corpus"))) {
            for (Path file : files.filter(p -> p.toString().endsWith(".json")).sorted().toList()) {
                JsonNode root = mapper.readTree(Files.readString(file));
                String ruleId = root.get("ruleId").asText();
                boolean isActive = active.contains(ruleId);

                for (String tp : samples(root, "truePositives", "pathTruePositives")) {
                    if (isActive && detector.detect(tp).stream().noneMatch(m -> m.rule().equals(ruleId))) {
                        activeFalseNegatives.merge(ruleId, 1, Integer::sum);
                    }
                }
                for (String fp : samples(root, "falsePositives", "pathFalsePositives")) {
                    if (isActive && detector.detect(fp).stream().anyMatch(m -> m.rule().equals(ruleId))) {
                        sameRuleFalsePositives.merge(ruleId, 1, Integer::sum);
                    }
                }
            }
        }

        assertThat(activeFalseNegatives)
                .as("every active rule must catch all of its upstream true positives")
                .isEmpty();
        assertThat(sameRuleFalsePositives)
                .as("no active rule may fire on an upstream false-positive sample")
                .isEmpty();
    }

    @Test
    void deferredRulesStillHaveMeasuredDeferralRationale() throws IOException {
        RulepackSource source = rulepackSource();
        assertThat(source.rules()).doesNotContainKey("pkcs12-file");

        // Since the executor adopted upstream's secret extraction (first non-empty capture
        // group when secretGroup is unset), generic-api-key is corpus-perfect: 63/63 true
        // positives, zero same-rule false positives. Its deferral is now precautionary only
        // (upstream's noisiest rule on real-world prose, which this corpus does not model);
        // activation is a policy decision tracked in docs/adr/0016's addendum.
        DeferralEvidence generic = evidenceForDeferredRule("generic-api-key", source);
        assertThat(generic.sameRuleTruePositives())
                .as("generic-api-key catches all upstream true positives under upstream group semantics")
                .isEqualTo(generic.truePositiveSamples());
        assertThat(generic.sameRuleFalsePositives())
                .as("generic-api-key stays clean on upstream false-positive samples")
                .isZero();

        // Upstream group semantics also cleared the curl rules' corpus false positives;
        // like generic-api-key their deferral is now precautionary. The other three still
        // fire on upstream FP samples, so their measured rationale stands.
        Map<String, Integer> falsePositiveEvidence = new TreeMap<>();
        for (String ruleId : FALSE_POSITIVE_DEFERRED) {
            falsePositiveEvidence.put(ruleId, evidenceForDeferredRule(ruleId, source).sameRuleFalsePositives());
        }
        assertThat(falsePositiveEvidence)
                .as("measured same-rule false positives of the FP-deferred rules (see docs/adr/0016)")
                .isEqualTo(Map.of(
                        "curl-auth-header", 0,
                        "curl-auth-user", 0,
                        "freemius-secret-key", 1,
                        "hashicorp-tf-password", 1,
                        "nuget-config-password", 1));
    }

    @Test
    void benignFixtureBodiesStayClean() throws IOException {
        Path bodies = Path.of("src/test/resources/scanner/bodies");
        for (String body : List.of("fp-code-snippet.json", "fp-dependency.json", "fp-prose.json")) {
            String text = Files.readString(bodies.resolve(body));
            assertThat(detector.detect(text))
                    .as("benign body %s must produce zero findings (Phase 3 FP budget)", body)
                    .isEmpty();
        }
    }

    @Test
    void harderBenignBodiesStayClean() {
        String base64Config = Base64.getEncoder().encodeToString("""
                service: hamza
                token_mode: disabled
                sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
                """.getBytes(StandardCharsets.UTF_8));

        List<String> benignBodies = List.of(
                """
                public final class Example {
                    UUID requestId = UUID.fromString("123e4567-e89b-12d3-a456-426614174000");
                    String digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
                    String authHeader = "Authorization: Bearer ${TOKEN}";
                }
                """,
                """
                lockfile:
                  integrity: sha512-8f14e45fceea167a5a36dedd4bea2543
                  revision: 9b2cf535f27731c974343645a3985328
                """,
                "{\"config\":\"" + base64Config + "\"}"
        );

        for (String body : benignBodies) {
            assertThat(detector.detect(body))
                    .as("harder benign body must stay clean: %s", body)
                    .isEmpty();
        }
    }

    // Fake AWS key that is not the canonical "…EXAMPLE" key (which the rule allowlists).
    private static final String FAKE_AWS_KEY = "AKIAABCDEFGHIJKLMNOP";

    @Test
    void decodeScannerCatchesSecretOneLevelDeepAsDecoded() {
        String encoded = Base64.getEncoder()
                .encodeToString(("access_key_id=" + FAKE_AWS_KEY).getBytes(StandardCharsets.UTF_8));
        List<SecretDetector.Match> matches = detector.detect("{\"blob\":\"" + encoded + "\"}");
        assertThat(matches)
                .as("a base64-wrapped AWS key must be caught as a decoded finding")
                .anyMatch(m -> m.decoded() && m.rule().equals("aws-access-token"));
    }

    @Test
    void decodeScannerReportsWholeOriginalEnvelopeSpan() {
        String encoded = Base64.getEncoder()
                .encodeToString(("access_key_id=" + FAKE_AWS_KEY).getBytes(StandardCharsets.UTF_8));
        String body = "{\"prefix\":true,\"blob\":\"" + encoded + "\",\"suffix\":true}";

        SecretDetector.Match decoded = detector.detect(body).stream()
                .filter(m -> m.decoded() && m.rule().equals("aws-access-token"))
                .findFirst()
                .orElseThrow();

        int start = body.indexOf(encoded);
        assertThat(decoded.start()).isEqualTo(start);
        assertThat(decoded.end()).isEqualTo(start + encoded.length());
        assertThat(body.substring(decoded.start(), decoded.end())).isEqualTo(encoded);
    }

    @Test
    void decodeScannerRepadsBase64WithoutDroppingDataBytes() {
        String encoded = Base64.getEncoder()
                .encodeToString(("access_key_id=" + FAKE_AWS_KEY).getBytes(StandardCharsets.UTF_8))
                .replace("=", "");

        assertThat(detector.detect("{\"blob\":\"" + encoded + "\"}"))
                .anyMatch(m -> m.decoded() && m.rule().equals("aws-access-token"));
    }

    @Test
    void decodeScannerCatchesUrlEncodedSecretAsDecoded() {
        String encoded = percentEncode("access_key_id=" + FAKE_AWS_KEY);
        String body = "{\"blob\":\"" + encoded + "\"}";

        SecretDetector.Match decoded = detector.detect(body).stream()
                .filter(m -> m.decoded() && m.rule().equals("aws-access-token"))
                .findFirst()
                .orElseThrow();

        int start = body.indexOf(encoded);
        assertThat(decoded.start()).isEqualTo(start);
        assertThat(decoded.end()).isEqualTo(start + encoded.length());
    }

    @Test
    void decodeScannerCatchesSecretSeveralLevelsDeep() {
        String payload = "access_key_id=" + FAKE_AWS_KEY;
        for (int i = 0; i < 3; i++) {
            payload = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        }
        List<SecretDetector.Match> matches = detector.detect("{\"blob\":\"" + payload + "\"}");
        assertThat(matches).anyMatch(m -> m.decoded() && m.rule().equals("aws-access-token"));
    }

    @Test
    void decodeScannerTerminatesOnPathologicalNesting() {
        String payload = "secret";
        for (int i = 0; i < 16; i++) {
            payload = Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        }
        String body = "{\"blob\":\"" + payload + "\"}";
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> detector.detect(body));
    }

    @Test
    void decodeScannerTerminatesOnHostileWideInputs() {
        String hugeBlob = Base64.getEncoder().encodeToString("x".repeat(300_000).getBytes(StandardCharsets.UTF_8));
        String manySmallBlobs = (Base64.getEncoder()
                .encodeToString("not a secret but long enough".getBytes(StandardCharsets.UTF_8)) + " ")
                .repeat(1_000);
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> detector.detect(hugeBlob));
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> detector.detect(manySmallBlobs));
    }

    private List<String> samples(JsonNode root, String flatField, String mapField) {
        List<String> out = new ArrayList<>();
        JsonNode flat = root.get(flatField);
        if (flat != null && flat.isArray()) {
            flat.forEach(n -> out.add(n.asText()));
        }
        JsonNode map = root.get(mapField);
        if (map != null && map.isObject()) {
            map.properties().forEach(e -> out.add(e.getValue().asText()));
        }
        return out;
    }

    private DeferralEvidence evidenceForDeferredRule(String ruleId, RulepackSource source) throws IOException {
        RulepackRule rule = source.rules().get(ruleId);
        assertThat(rule).as("deferred rule must still exist in the rulepack: %s", ruleId).isNotNull();
        List<RulepackAllowlist> allowlists = new ArrayList<>(source.globalAllowlists());
        allowlists.addAll(rule.allowlists());
        SecretDetector oneRuleDetector = new SecretDetector(new RulepackExecutor(List.of(
                new RulepackExecutor.RuleSpec(ruleId, rule.regex(),
                        rule.secretGroup() == null ? 0 : rule.secretGroup(),
                        rule.entropy() == null ? 0.0 : rule.entropy(),
                        rule.keywords(), allowlists))));

        JsonNode root = mapper.readTree(Files.readString(
                Path.of("src/test/resources/scanner/rulepack-corpus").resolve(ruleId + ".json")));
        int tp = 0;
        int tpSame = 0;
        int fpSame = 0;
        for (String sample : samples(root, "truePositives", "pathTruePositives")) {
            tp++;
            if (oneRuleDetector.detect(sample).stream().anyMatch(m -> m.rule().equals(ruleId))) {
                tpSame++;
            }
        }
        for (String sample : samples(root, "falsePositives", "pathFalsePositives")) {
            if (oneRuleDetector.detect(sample).stream().anyMatch(m -> m.rule().equals(ruleId))) {
                fpSame++;
            }
        }
        return new DeferralEvidence(tp, tpSame, fpSame);
    }

    private RulepackSource rulepackSource() throws IOException {
        JsonNode root = mapper.readTree(Files.readString(Path.of("src/main/resources/rulepack/rulepack.json")));
        List<RulepackAllowlist> globalAllowlists = new ArrayList<>();
        root.path("globalAllowlists").forEach(node ->
                globalAllowlists.add(mapper.convertValue(node, RulepackAllowlist.class)));
        Map<String, RulepackRule> rules = new LinkedHashMap<>();
        root.path("rules").forEach(node -> {
            RulepackRule rule = mapper.convertValue(node, RulepackRule.class);
            rules.put(rule.id(), rule);
        });
        return new RulepackSource(rules, globalAllowlists);
    }

    private record RulepackSource(Map<String, RulepackRule> rules, List<RulepackAllowlist> globalAllowlists) {
    }

    private record DeferralEvidence(int truePositiveSamples, int sameRuleTruePositives,
                                    int sameRuleFalsePositives) {
    }

    private static String percentEncode(String text) {
        StringBuilder out = new StringBuilder(text.length() * 3);
        for (byte b : text.getBytes(StandardCharsets.UTF_8)) {
            out.append('%');
            out.append(Character.toUpperCase(Character.forDigit((b >> 4) & 0xf, 16)));
            out.append(Character.toUpperCase(Character.forDigit(b & 0xf, 16)));
        }
        return out.toString();
    }
}
