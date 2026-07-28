package ai.hamza.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Un-escapes JSON string escapes in an Egress body and re-scans the result for secrets.
 *
 * <p>Coding-agent CLIs JSON-encode the developer's message, so a secret written in source
 * or config as {@code key = "AKIA…"} reaches the Gate as {@code key = \"AKIA…\"}. The
 * file-format rule regexes (imported from gitleaks/Betterleaks) put a literal-quote class
 * right before the captured value, and that class excludes the backslash, so the raw-wire
 * scan misses every quoted assignment. Un-escaping {@code \"}→{@code "} (and the other JSON
 * escapes) before matching recovers them.
 *
 * <p>Like {@link DecodeScanner}, a match found only after un-escaping is reported against a
 * span in the <strong>original</strong> text (via an index map) and flagged
 * {@code decoded=true}, so the policy layer withholds masking (FLAG/BLOCK only): rewriting
 * a value that straddles JSON escape boundaries has no safe span in the original body. The
 * block decision is unaffected — "block wins" still holds.
 */
final class JsonUnescapeScanner {

    private final Function<String, List<SecretDetector.Match>> scan;

    JsonUnescapeScanner(Function<String, List<SecretDetector.Match>> scan) {
        this.scan = scan;
    }

    /**
     * Un-escape {@code text} and re-scan; returns matches that the un-escaping newly exposes,
     * each mapped back to the original span and marked {@code decoded}. Returns empty when the
     * text carries no backslash escape (the common case) so the hot path pays nothing.
     */
    List<SecretDetector.Match> scanUnescaped(String text, List<SecretDetector.Match> directMatches) {
        int firstEscape = text.indexOf('\\');
        if (firstEscape < 0) {
            return List.of();
        }
        Unescaped u = unescape(text, firstEscape);
        if (u == null || u.text.equals(text)) {
            return List.of();
        }
        List<SecretDetector.Match> found = scan.apply(u.text);
        if (found.isEmpty()) {
            return List.of();
        }
        List<SecretDetector.Match> out = new ArrayList<>();
        for (SecretDetector.Match m : found) {
            int start = u.map[m.start()];
            int end = u.map[m.end()];
            // Skip anything the raw scan already caught at the same rule+span — the un-escape
            // pass is only for quote-evading secrets, not for double-reporting.
            if (coveredByDirect(directMatches, m.rule(), start, end)) {
                continue;
            }
            out.add(new SecretDetector.Match(m.rule(), start, end, true));
        }
        return out;
    }

    private static boolean coveredByDirect(List<SecretDetector.Match> direct, String rule,
                                           int start, int end) {
        for (SecretDetector.Match d : direct) {
            if (d.rule().equals(rule) && d.start() < end && start < d.end()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Build the un-escaped string plus {@code map}, where {@code map[i]} is the index in the
     * original text at which the i-th un-escaped char begins ({@code map[len]} = original end),
     * so an un-escaped span [s,e) maps to the original span [map[s], map[e]).
     */
    private static Unescaped unescape(String text, int firstEscape) {
        int n = text.length();
        StringBuilder sb = new StringBuilder(n);
        int[] map = new int[n + 1];
        // Everything before the first backslash is copied verbatim (1:1 index mapping).
        for (int i = 0; i < firstEscape; i++) {
            map[sb.length()] = i;
            sb.append(text.charAt(i));
        }
        int i = firstEscape;
        while (i < n) {
            char c = text.charAt(i);
            if (c != '\\' || i + 1 >= n) {
                map[sb.length()] = i;
                sb.append(c);
                i++;
                continue;
            }
            char esc = text.charAt(i + 1);
            int origStart = i;
            char decoded;
            int consumed;
            switch (esc) {
                case '"' -> {
                    decoded = '"';
                    consumed = 2;
                }
                case '\\' -> {
                    decoded = '\\';
                    consumed = 2;
                }
                case '/' -> {
                    decoded = '/';
                    consumed = 2;
                }
                case 'n' -> {
                    decoded = '\n';
                    consumed = 2;
                }
                case 't' -> {
                    decoded = '\t';
                    consumed = 2;
                }
                case 'r' -> {
                    decoded = '\r';
                    consumed = 2;
                }
                case 'b' -> {
                    decoded = '\b';
                    consumed = 2;
                }
                case 'f' -> {
                    decoded = '\f';
                    consumed = 2;
                }
                case 'u' -> {
                    int cp = hex4(text, i + 2);
                    if (cp < 0) {
                        map[sb.length()] = i;
                        sb.append(c);
                        i++;
                        continue;
                    }
                    decoded = (char) cp;
                    consumed = 6;
                }
                default -> {
                    // Not a JSON escape; keep the backslash verbatim.
                    map[sb.length()] = i;
                    sb.append(c);
                    i++;
                    continue;
                }
            }
            map[sb.length()] = origStart;
            sb.append(decoded);
            i += consumed;
        }
        map[sb.length()] = n;
        return new Unescaped(sb.toString(), map);
    }

    private static int hex4(String text, int at) {
        if (at + 4 > text.length()) {
            return -1;
        }
        int v = 0;
        for (int k = 0; k < 4; k++) {
            int d = Character.digit(text.charAt(at + k), 16);
            if (d < 0) {
                return -1;
            }
            v = (v << 4) | d;
        }
        return v;
    }

    private record Unescaped(String text, int[] map) {
    }
}
