package ai.hamza.policy;

import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;

/**
 * Replaces matched secret spans with the existing single-Turn compatibility marker
 * {@code «redacted:<rule>»}, returning the masked body. The marker format is retained
 * only to preserve pre-M1 behavior; it is not an M2 stable Placeholder. The matched
 * value never appears in the output (content-free invariant).
 */
@Component
public class Masker {

    /** Mask the given spans from {@code text}. Overlapping spans are merged. */
    public String mask(String text, List<SecretDetector.Match> matches) {
        if (matches == null || matches.isEmpty()) {
            return text;
        }
        List<SecretDetector.Match> sorted = matches.stream()
                .sorted(Comparator.comparingInt(SecretDetector.Match::start)
                        .thenComparingInt(SecretDetector.Match::end))
                .toList();

        StringBuilder out = new StringBuilder(text.length());
        int cursor = 0;
        for (SecretDetector.Match m : sorted) {
            int start = Math.max(m.start(), cursor);
            if (m.end() <= cursor) {
                continue; // fully covered by an earlier overlapping mask
            }
            if (start > cursor) {
                out.append(text, cursor, start);
            }
            out.append("«redacted:").append(m.rule()).append('»');
            cursor = m.end();
        }
        if (cursor < text.length()) {
            out.append(text, cursor, text.length());
        }
        return out.toString();
    }
}
