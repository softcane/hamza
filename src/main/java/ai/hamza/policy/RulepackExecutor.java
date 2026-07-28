package ai.hamza.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class RulepackExecutor {

    private final List<CompiledRule> rules;

    RulepackExecutor(List<RuleSpec> ruleSpecs) {
        rules = ruleSpecs.stream().map(CompiledRule::new).toList();
    }

    List<SecretDetector.Match> detect(String text) {
        String lowerText = null;
        List<SecretDetector.Match> matches = new ArrayList<>();
        for (CompiledRule rule : rules) {
            if (rule.hasKeywords()) {
                if (lowerText == null) {
                    lowerText = text.toLowerCase(Locale.ROOT);
                }
                if (!rule.keywordFoundIn(lowerText)) {
                    continue;
                }
            }
            Matcher matcher = rule.pattern().matcher(text);
            while (matcher.find()) {
                Candidate candidate = candidate(rule, matcher);
                if (candidate == null) {
                    continue;
                }
                String line = rule.hasLineAllowlist() ? lineAround(text, matcher.start(), matcher.end()) : "";
                if (rule.allowed(candidate, matcher.group(), line)) {
                    continue;
                }
                if (rule.minEntropyBitsPerChar() > 0.0
                        && SecretDetector.shannonEntropyPerChar(candidate.value()) < rule.minEntropyBitsPerChar()) {
                    continue;
                }
                matches.add(new SecretDetector.Match(rule.emittedId(), candidate.start(), candidate.end()));
            }
        }
        return matches;
    }

    int ruleCount() {
        return rules.size();
    }

    List<String> ruleIds() {
        return rules.stream().map(CompiledRule::emittedId).toList();
    }

    private static Candidate candidate(CompiledRule rule, Matcher matcher) {
        int group = rule.secretGroup();
        if (group == 0) {
            // Upstream (gitleaks detect.go): with no secretGroup, the secret is the first
            // non-empty capture group, so entropy/stopword/secret-target filters judge the
            // secret itself, not surrounding syntax like the variable name. The full match
            // is the secret only when the regex captures nothing.
            for (int g = 1; g <= matcher.groupCount(); g++) {
                if (matcher.start(g) >= 0 && matcher.end(g) > matcher.start(g)) {
                    return new Candidate(matcher.start(g), matcher.end(g), matcher.group(g));
                }
            }
            return new Candidate(matcher.start(), matcher.end(), matcher.group());
        }
        if (group > matcher.groupCount()) {
            throw new IllegalStateException("Rule " + rule.emittedId() + " refers to missing secretGroup " + group);
        }
        int start = matcher.start(group);
        int end = matcher.end(group);
        if (start < 0 || end < 0) {
            return null;
        }
        return new Candidate(start, end, matcher.group(group));
    }

    /** The line (bounded by \n or text edges) enclosing the match — upstream's allowlist "line" target. */
    private static String lineAround(String text, int start, int end) {
        int lineStart = text.lastIndexOf('\n', start - 1) + 1;
        int lineEnd = text.indexOf('\n', end);
        if (lineEnd < 0) {
            lineEnd = text.length();
        }
        return text.substring(lineStart, lineEnd);
    }

    private static List<String> normalizeKeywords(List<String> keywords) {
        return keywords.stream()
                .filter(keyword -> keyword != null && !keyword.isBlank())
                .map(keyword -> keyword.toLowerCase(Locale.ROOT))
                .distinct()
                .toList();
    }

    record RuleSpec(String emittedId,
                    String regex,
                    int secretGroup,
                    double minEntropyBitsPerChar,
                    List<String> keywords,
                    List<RulepackAllowlist> allowlists) {
        RuleSpec {
            keywords = keywords == null ? List.of() : List.copyOf(keywords);
            allowlists = allowlists == null ? List.of() : List.copyOf(allowlists);
        }
    }

    private record CompiledRule(String emittedId,
                                Pattern pattern,
                                int secretGroup,
                                double minEntropyBitsPerChar,
                                List<String> keywords,
                                List<CompiledAllowlist> allowlists) {
        CompiledRule(RuleSpec spec) {
            this(spec.emittedId(), Pattern.compile(spec.regex()), spec.secretGroup(),
                    spec.minEntropyBitsPerChar(), normalizeKeywords(spec.keywords()),
                    spec.allowlists().stream().map(CompiledAllowlist::new).toList());
        }

        boolean hasKeywords() {
            return !keywords.isEmpty();
        }

        boolean hasLineAllowlist() {
            for (CompiledAllowlist allowlist : allowlists) {
                if ("line".equals(allowlist.regexTarget())) {
                    return true;
                }
            }
            return false;
        }

        boolean keywordFoundIn(String lowerText) {
            for (String keyword : keywords) {
                if (lowerText.contains(keyword)) {
                    return true;
                }
            }
            return false;
        }

        boolean allowed(Candidate candidate, String fullMatch, String line) {
            for (CompiledAllowlist allowlist : allowlists) {
                if (allowlist.allowed(candidate.value(), fullMatch, line)) {
                    return true;
                }
            }
            return false;
        }
    }

    private record CompiledAllowlist(String regexTarget,
                                     List<Pattern> regexes,
                                     List<String> stopwords) {
        CompiledAllowlist(RulepackAllowlist allowlist) {
            this(allowlist.regexTarget() == null ? "" : allowlist.regexTarget(),
                    allowlist.regexes().stream().map(Pattern::compile).toList(),
                    normalizeKeywords(allowlist.stopwords()));
        }

        boolean allowed(String candidate, String fullMatch, String line) {
            // Allow-regexes run against the configured target (match/line/secret); stopwords
            // always run against the captured secret, matching upstream's evaluation (the
            // stopword guards a noisy secret, not the surrounding syntax).
            String target = switch (regexTarget) {
                case "match" -> fullMatch;
                case "line" -> line;
                default -> candidate;
            };
            for (Pattern regex : regexes) {
                if (regex.matcher(target).find()) {
                    return true;
                }
            }
            if (!stopwords.isEmpty()) {
                String lowerSecret = candidate.toLowerCase(Locale.ROOT);
                for (String stopword : stopwords) {
                    if (lowerSecret.contains(stopword)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    private record Candidate(int start, int end, String value) {
    }
}
