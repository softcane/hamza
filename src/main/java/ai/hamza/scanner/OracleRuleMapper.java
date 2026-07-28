package ai.hamza.scanner;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Normalises a raw Oracle {@code RuleID} into a stable Hamza rule id (GrillMe Q15).
 *
 * <p>When the checked-in Rulepack activates the same content rule natively, it maps to
 * the emitted Rulepack id so policy, metrics, and dedup stay consistent. Every disabled
 * oracle-only rule maps to the namespaced {@code oracle:<rule-id>} form so an
 * upstream rule-pack change can never silently collide with a Hamza id.
 *
 * <p>This is the single source of truth for the mapping — used by the offline oracle
 * parser and by dedup. It stores no secret values.
 */
@Component
public class OracleRuleMapper {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String RULEPACK_RESOURCE = "/rulepack/rulepack.json";
    private static final String ACTIVATION_RESOURCE = "/rulepack/phase1-active-rules.json";

    /** Oracle rule id or legacy alias → emitted Hamza Rulepack id. */
    private static final Map<String, String> NATIVE_EQUIVALENTS = loadNativeEquivalents();

    /**
     * Map a raw Oracle rule id to a stable Hamza id: the native equivalent when one
     * exists, otherwise {@code oracle:<rule-id>}.
     */
    public String toStableId(String oracleRuleId) {
        if (oracleRuleId == null || oracleRuleId.isBlank()) {
            throw new IllegalArgumentException("oracle rule id must be non-blank");
        }
        String id = oracleRuleId.trim();
        String mapped = NATIVE_EQUIVALENTS.get(id);
        return mapped != null ? mapped : "oracle:" + id;
    }

    /** True if Hamza detects this Oracle rule natively (so results should be deduped). */
    public boolean hasNativeEquivalent(String oracleRuleId) {
        return oracleRuleId != null && NATIVE_EQUIVALENTS.containsKey(oracleRuleId.trim());
    }

    /**
     * Confidence for a normalised finding. A native equivalent is a rule Hamza already
     * trusts enough to run in-process → {@link Confidence#HIGH}. A namespaced
     * oracle-only rule is unproven here → {@link Confidence#MEDIUM} (defaults to FLAG).
     */
    public Confidence confidenceFor(String oracleRuleId) {
        return hasNativeEquivalent(oracleRuleId) ? Confidence.HIGH : Confidence.MEDIUM;
    }

    private static Map<String, String> loadNativeEquivalents() {
        Rulepack rulepack = read(RULEPACK_RESOURCE, Rulepack.class);
        Activation activation = read(ACTIVATION_RESOURCE, Activation.class);
        Set<String> activeIds = new HashSet<>(activation.activeRuleIds());
        Set<String> localIds = new HashSet<>();
        for (Rule rule : activation.localRules()) {
            localIds.add(rule.id());
        }

        Map<String, String> out = new HashMap<>();
        for (Rule rule : rulepack.rules()) {
            String emittedId = emittedIdFor(rule, activeIds, localIds);
            if (emittedId == null) {
                continue;
            }
            out.put(rule.id(), emittedId);
            for (String alias : rule.aliases()) {
                out.put(alias, emittedId);
            }
        }
        return Map.copyOf(out);
    }

    private static String emittedIdFor(Rule rule, Set<String> activeIds, Set<String> localIds) {
        if (activeIds.contains(rule.id()) && !localIds.contains(rule.id())) {
            return rule.id();
        }
        for (String alias : rule.aliases()) {
            if (activeIds.contains(alias) && !localIds.contains(alias)) {
                return alias;
            }
        }
        return null;
    }

    private static <T> T read(String resource, Class<T> type) {
        try (InputStream in = OracleRuleMapper.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Missing Rulepack resource: " + resource);
            }
            return OBJECT_MAPPER.readValue(in, type);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read Rulepack resource: " + resource, e);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record Rulepack(List<Rule> rules) {
        Rulepack {
            rules = rules == null ? List.of() : List.copyOf(rules);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record Activation(List<String> activeRuleIds, List<Rule> localRules) {
        Activation {
            activeRuleIds = activeRuleIds == null ? List.of() : List.copyOf(activeRuleIds);
            localRules = localRules == null ? List.of() : List.copyOf(localRules);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record Rule(String id, List<String> aliases) {
        Rule {
            aliases = aliases == null ? List.of() : List.copyOf(aliases);
        }
    }
}
