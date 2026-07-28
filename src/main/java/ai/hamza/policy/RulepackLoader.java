package ai.hamza.policy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class RulepackLoader {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String RULEPACK_RESOURCE = "/rulepack/rulepack.json";
    private static final String ACTIVATION_RESOURCE = "/rulepack/phase1-active-rules.json";

    private RulepackLoader() {
    }

    static RulepackExecutor loadDefault() {
        return load(RULEPACK_RESOURCE, ACTIVATION_RESOURCE);
    }

    static RulepackExecutor load(String rulepackResource, String activationResource) {
        Rulepack rulepack = read(rulepackResource, Rulepack.class);
        RulepackActivation activation = read(activationResource, RulepackActivation.class);
        Map<String, RulepackRule> upstreamLookup = upstreamLookup(rulepack.rules());
        Map<String, RulepackRule> localRules = byId(activation.localRules());
        List<RulepackAllowlist> globalAllowlists = rulepack.globalAllowlists();

        List<RulepackExecutor.RuleSpec> activeRules = new ArrayList<>();
        for (String activeId : activation.activeRuleIds()) {
            RulepackRule rule = localRules.getOrDefault(activeId, upstreamLookup.get(activeId));
            if (rule == null) {
                throw new IllegalStateException("Active Rulepack id not found: " + activeId);
            }
            List<RulepackAllowlist> allowlists = new ArrayList<>(globalAllowlists);
            allowlists.addAll(rule.allowlists());
            activeRules.add(new RulepackExecutor.RuleSpec(activeId, rule.regex(),
                    rule.secretGroup() == null ? 0 : rule.secretGroup(),
                    rule.entropy() == null ? 0.0 : rule.entropy(),
                    rule.keywords(), allowlists));
        }
        return new RulepackExecutor(activeRules);
    }

    private static Map<String, RulepackRule> upstreamLookup(List<RulepackRule> rules) {
        Map<String, RulepackRule> lookup = new HashMap<>();
        for (RulepackRule rule : rules) {
            lookup.put(rule.id(), rule);
            for (String alias : rule.aliases()) {
                lookup.putIfAbsent(alias, rule);
            }
        }
        return lookup;
    }

    private static Map<String, RulepackRule> byId(List<RulepackRule> rules) {
        Map<String, RulepackRule> out = new LinkedHashMap<>();
        for (RulepackRule rule : rules) {
            RulepackRule previous = out.put(rule.id(), rule);
            if (previous != null) {
                throw new IllegalStateException("Duplicate local Rulepack id: " + rule.id());
            }
        }
        return out;
    }

    private static <T> T read(String resource, Class<T> type) {
        try (InputStream in = RulepackLoader.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Missing Rulepack resource: " + resource);
            }
            return OBJECT_MAPPER.readValue(in, type);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read Rulepack resource: " + resource, e);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record Rulepack(List<RulepackRule> rules, List<RulepackAllowlist> globalAllowlists) {
        Rulepack {
            rules = rules == null ? List.of() : List.copyOf(rules);
            globalAllowlists = globalAllowlists == null ? List.of() : List.copyOf(globalAllowlists);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record RulepackActivation(List<String> activeRuleIds, List<RulepackRule> localRules) {
        RulepackActivation {
            activeRuleIds = activeRuleIds == null ? List.of() : List.copyOf(activeRuleIds);
            localRules = localRules == null ? List.of() : List.copyOf(localRules);
        }
    }
}
