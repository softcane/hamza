package ai.hamza.policy;

import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;

/**
 * Replaces detected spans with the stable Placeholders the caller supplies, returning the
 * masked body. The Masker owns span arithmetic only: it decides nothing about which value
 * gets which Placeholder, so the same value can carry one identity across a whole body.
 *
 * <p>Overlapping spans are merged, never nested: the earlier span owns the shared text and
 * the later one is clamped to what is left of it, because a Placeholder written inside
 * another Placeholder would not survive the rescan. A span the merge leaves with no text
 * of its own still renders its Placeholder, next to the one that covered it — dropping it
 * would leave a detected value with a Finding and nothing on the wire to show for it. The
 * matched value never appears in the output (content-free invariant).
 */
@Component
public class Masker {

    /**
     * One span of the source body and the Placeholder that replaces it.
     *
     * @param start       inclusive char offset into the body
     * @param end         exclusive char offset into the body
     * @param placeholder the rendered Placeholder, e.g. {@code <SECRET_730044>}
     */
    public record Replacement(int start, int end, String placeholder) {
        public Replacement {
            if (start < 0 || end <= start) {
                throw new IllegalArgumentException("replacement span must be non-empty");
            }
            if (placeholder == null || placeholder.isBlank()) {
                throw new IllegalArgumentException("replacement needs a placeholder");
            }
        }
    }

    /** Mask the given spans from {@code text}. Overlapping spans are merged, never dropped. */
    public String mask(String text, List<Replacement> replacements) {
        if (replacements == null || replacements.isEmpty()) {
            return text;
        }
        List<Replacement> sorted = replacements.stream()
                .sorted(Comparator.comparingInt(Replacement::start)
                        .thenComparingInt(Replacement::end))
                .toList();

        StringBuilder out = new StringBuilder(text.length());
        int cursor = 0;
        String previous = null;
        for (Replacement r : sorted) {
            if (r.end() <= cursor) {
                // Fully inside a span already masked: its text is gone, but the mask it
                // stands for must still be visible, so the Placeholder is emitted beside
                // the covering one instead of being swallowed. An identical span already
                // rendered by that mask adds nothing and is not repeated.
                if (!r.placeholder().equals(previous)) {
                    out.append(r.placeholder());
                    previous = r.placeholder();
                }
                continue;
            }
            int start = Math.max(r.start(), cursor);
            if (start > cursor) {
                out.append(text, cursor, start);
            }
            out.append(r.placeholder());
            previous = r.placeholder();
            cursor = r.end();
        }
        if (cursor < text.length()) {
            out.append(text, cursor, text.length());
        }
        return out.toString();
    }
}
