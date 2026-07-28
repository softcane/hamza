package ai.hamza.policy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guard for checked-in Rulepack data. The generated full pack must compile as Java
 * regexes; Phase 2 wires the explicit vendor activation set into the hot path.
 */
class RulepackCompileTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void generatedRulepackContainsEveryContentRuleAndCompilesAsJavaRegex() throws Exception {
        JsonNode root = readRulepack();
        JsonNode rules = root.get("rules");

        assertThat(root.get("upstreamRules").asInt()).isEqualTo(222);
        assertThat(rules).hasSize(221);
        assertThat(root.get("skippedRules").get(0).get("id").asText()).isEqualTo("pkcs12-file");

        List<String> failures = new ArrayList<>();
        for (JsonNode rule : rules) {
            compile(failures, rule.get("id").asText(), "regex", rule.get("regex").asText());
            compileOptional(failures, rule.get("id").asText(), "path", rule.get("path"));
            for (JsonNode allowlist : array(rule, "allowlists")) {
                for (JsonNode regex : array(allowlist, "regexes")) {
                    compile(failures, rule.get("id").asText(), "allowlist regex", regex.asText());
                }
                for (JsonNode path : array(allowlist, "paths")) {
                    compile(failures, rule.get("id").asText(), "allowlist path", path.asText());
                }
            }
        }
        for (JsonNode allowlist : array(root, "globalAllowlists")) {
            for (JsonNode regex : array(allowlist, "regexes")) {
                compile(failures, "<global>", "allowlist regex", regex.asText());
            }
            for (JsonNode path : array(allowlist, "paths")) {
                compile(failures, "<global>", "allowlist path", path.asText());
            }
        }

        assertThat(failures).as("Java regex compile failures").isEmpty();
    }

    @Test
    void phase3ActivationCompilesAndDocumentsDisabledRules() throws Exception {
        JsonNode root = readJson("/rulepack/phase1-active-rules.json");
        JsonNode activeRuleIds = root.get("activeRuleIds");
        JsonNode localRules = root.get("localRules");
        JsonNode excludedRuleIds = root.get("excludedRuleIds");

        assertThat(activeRuleIds).hasSize(327);
        assertThat(localRules).hasSize(112);
        assertThat(excludedRuleIds.get("generic")).extracting(JsonNode::asText).containsExactly(
                "curl-auth-header",
                "curl-auth-user",
                "generic-api-key"
        );
        assertThat(excludedRuleIds.get("pathScoped")).extracting(JsonNode::asText).containsExactly(
                "freemius-secret-key",
                "hashicorp-tf-password",
                "nuget-config-password"
        );
        assertThat(excludedRuleIds.get("pathOnlySkipped")).extracting(JsonNode::asText)
                .containsExactly("pkcs12-file");

        List<String> failures = new ArrayList<>();
        for (JsonNode rule : localRules) {
            compile(failures, rule.get("id").asText(), "regex", rule.get("regex").asText());
        }

        assertThat(failures).as("Phase 2 local regex compile failures").isEmpty();
    }

    private JsonNode readRulepack() throws Exception {
        return readJson("/rulepack/rulepack.json");
    }

    private JsonNode readJson(String resource) throws Exception {
        try (InputStream in = RulepackCompileTest.class.getResourceAsStream(resource)) {
            assertThat(in).as("%s resource", resource).isNotNull();
            return objectMapper.readTree(in);
        }
    }

    private static void compileOptional(List<String> failures, String id, String field, JsonNode value) {
        if (value != null && !value.asText().isBlank()) {
            compile(failures, id, field, value.asText());
        }
    }

    private static void compile(List<String> failures, String id, String field, String regex) {
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            failures.add(id + " " + field + ": " + e.getDescription());
        }
    }

    private static JsonNode array(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || !value.isArray() ? com.fasterxml.jackson.databind.node.MissingNode.getInstance() : value;
    }
}
