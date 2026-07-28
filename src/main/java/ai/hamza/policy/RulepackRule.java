package ai.hamza.policy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
record RulepackRule(String id,
                    List<String> aliases,
                    String description,
                    String regex,
                    Integer secretGroup,
                    Double entropy,
                    List<String> keywords,
                    List<RulepackAllowlist> allowlists) {
    RulepackRule {
        aliases = aliases == null ? List.of() : List.copyOf(aliases);
        keywords = keywords == null ? List.of() : List.copyOf(keywords);
        allowlists = allowlists == null ? List.of() : List.copyOf(allowlists);
    }
}
