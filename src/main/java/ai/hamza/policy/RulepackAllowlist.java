package ai.hamza.policy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
record RulepackAllowlist(String regexTarget,
                         List<String> regexes,
                         List<String> stopwords) {
    RulepackAllowlist {
        regexes = regexes == null ? List.of() : List.copyOf(regexes);
        stopwords = stopwords == null ? List.of() : List.copyOf(stopwords);
    }
}
