package ai.hamza.policy;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.nio.charset.StandardCharsets;

/**
 * Detects secrets/credentials in outbound Egress (the request body only — never the
 * provider-auth headers, the content-free invariant). Rules are loaded from the checked-in Rulepack resources
 * and executed in-process on the Java hot path.
 *
 * <p>A {@link Match} carries the rule name and the span [start, end) in the scanned
 * text — never persisted; used only to build content-free {@link Finding}s and to
 * drive masking. The matched value itself is never stored or logged.
 */
@Component
public class SecretDetector {

    public static final String DETECTOR_ID = "secret";
    public static final String DETECTOR_VERSION = "rulepack-v1";

    /**
     * A single detection: which rule, where in the scanned text, and whether the
     * span was found inside a decoded (base64/URL) segment. A {@code decoded} match's
     * span points at the whole encoding envelope in the original text, so it is
     * FLAG/BLOCK-only — never masked (Rulepack Phase 3; see {@link DecodeScanner}).
     */
    public record Match(String rule, int start, int end, boolean decoded) {
        public Match(String rule, int start, int end) {
            this(rule, start, end, false);
        }
    }

    private final RulepackExecutor executor;
    private final DecodeScanner decodeScanner;
    private final JsonUnescapeScanner jsonUnescapeScanner;
    private static final int MAX_SCAN_WINDOW_CHARS = 32 * 1024;
    private static final int SCAN_OVERLAP_CHARS = 4 * 1024;

    public SecretDetector() {
        this(RulepackLoader.loadDefault());
    }

    SecretDetector(RulepackExecutor executor) {
        this.executor = executor;
        this.decodeScanner = new DecodeScanner(executor::detect);
        this.jsonUnescapeScanner = new JsonUnescapeScanner(executor::detect);
    }

    /**
     * Scan {@code text} for all matches across all rules, then decode base64/URL
     * segments and re-scan them (depth-capped). Direct matches come first, decoded
     * matches after.
     */
    public List<Match> detect(String text) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        if (text.length() > MAX_SCAN_WINDOW_CHARS) {
            return detectChunked(text);
        }
        return detectWindow(text, 0);
    }

    DetectionRun run(String text, List<Match> matches, long durationMicros) {
        String value = text == null ? "" : text;
        List<DetectionFinding> findings = matches.stream().map(match -> {
            boolean reliable = !match.decoded();
            Integer start = reliable ? value.codePointCount(0, match.start()) : null;
            Integer end = reliable ? value.codePointCount(0, match.end()) : null;
            return new DetectionFinding(match.rule(), Action.FLAG,
                    reliable ? "body" : null, start, end, null, reliable);
        }).toList();
        long bytes = value.getBytes(StandardCharsets.UTF_8).length;
        return new DetectionRun(DETECTOR_ID, DETECTOR_VERSION, DetectionStatus.COMPLETE,
                java.util.Optional.empty(), 1, 1, bytes, bytes,
                Math.max(0, durationMicros), findings);
    }

    private List<Match> detectChunked(String text) {
        List<Match> matches = new java.util.ArrayList<>();
        Set<String> emitted = new LinkedHashSet<>();
        int start = 0;
        while (start < text.length()) {
            int end = Math.min(text.length(), start + MAX_SCAN_WINDOW_CHARS);
            int scanStart = Math.max(0, start - SCAN_OVERLAP_CHARS);
            for (Match match : detectWindow(text.substring(scanStart, end), scanStart)) {
                if (match.end() <= start && start > 0) {
                    continue;
                }
                String key = match.rule() + ':' + match.start() + ':' + match.end() + ':' + match.decoded();
                if (emitted.add(key)) {
                    matches.add(match);
                }
            }
            start = end;
        }
        return matches;
    }

    private List<Match> detectWindow(String text, int offset) {
        if (lowSignalFiller(text)) {
            return List.of();
        }
        List<Match> matches = new java.util.ArrayList<>(executor.detect(text));
        matches.addAll(decodeScanner.scanEncoded(text));
        matches.addAll(jsonUnescapeScanner.scanUnescaped(text, matches));
        if (offset == 0 || matches.isEmpty()) {
            return matches;
        }
        return matches.stream()
                .map(match -> new Match(match.rule(), match.start() + offset,
                        match.end() + offset, match.decoded()))
                .toList();
    }

    private static boolean lowSignalFiller(String text) {
        if (text.length() < 4_096) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c > 0x7f || Character.isUpperCase(c) || Character.isDigit(c)
                    || c == '_' || c == '-' || c == '.' || c == '/' || c == '+'
                    || c == '=' || c == '%' || c == '@') {
                return false;
            }
        }
        return true;
    }

    /**
     * Shannon entropy in bits per character — a cheap randomness signal. Counts full
     * Unicode codepoints (not ASCII-only) so per-rule entropy thresholds imported from
     * upstream, which counts runes, transfer exactly.
     */
    static double shannonEntropyPerChar(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }
        Map<Integer, Integer> counts = new HashMap<>();
        int considered = 0;
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            counts.merge(cp, 1, Integer::sum);
            considered++;
        }
        if (considered == 0) {
            return 0.0;
        }
        double entropy = 0.0;
        for (int count : counts.values()) {
            double p = (double) count / considered;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }
}
