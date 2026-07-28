package ai.hamza.policy;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Span arithmetic: overlapping masks merge, and no mask is silently swallowed. */
class MaskerTest {

    private static final String AWS_KEY = "AKIAABCDEFGHIJKLMNOP";
    private final Masker masker = new Masker();

    /**
     * A wide span (a URL) covering a narrower one (the key in its query string) used to
     * suppress the inner mask outright: the Finding claimed a Mask that nothing on the wire
     * showed. Both Placeholders must render, and neither raw value may survive.
     */
    @Test
    void aWideSpanNoLongerSwallowsTheMaskInsideIt() {
        String text = "see https://ops.example.test/run?key=" + AWS_KEY + " now";
        int urlStart = text.indexOf("https://");
        int urlEnd = text.indexOf(" now");
        int keyStart = text.indexOf(AWS_KEY);

        String masked = masker.mask(text, List.of(
                new Masker.Replacement(urlStart, urlEnd, "<PII_11>"),
                new Masker.Replacement(keyStart, keyStart + AWS_KEY.length(), "<SECRET_22>")));

        assertThat(masked).isEqualTo("see <PII_11><SECRET_22> now");
        assertThat(masked).doesNotContain(AWS_KEY).doesNotContain("ops.example.test");
    }

    /** A partial overlap still merges: the earlier span owns the shared text. */
    @Test
    void partiallyOverlappingSpansMergeWithoutLosingEitherPlaceholder() {
        String masked = masker.mask("alpha beta gamma", List.of(
                new Masker.Replacement(0, 10, "<SECRET_1>"),
                new Masker.Replacement(6, 16, "<SECRET_2>")));

        assertThat(masked).isEqualTo("<SECRET_1><SECRET_2>");
    }

    /** One value detected twice at the same span renders one Placeholder, not two. */
    @Test
    void anIdenticalSpanRendersOnce() {
        String masked = masker.mask("mail " + AWS_KEY + " out", List.of(
                new Masker.Replacement(5, 5 + AWS_KEY.length(), "<SECRET_7>"),
                new Masker.Replacement(5, 5 + AWS_KEY.length(), "<SECRET_7>")));

        assertThat(masked).isEqualTo("mail <SECRET_7> out");
    }

    /** Disjoint spans are replaced in place and the rest of the body is untouched. */
    @Test
    void disjointSpansKeepTheSurroundingText() {
        String masked = masker.mask("a BBB c DDD e", List.of(
                new Masker.Replacement(2, 5, "<SECRET_1>"),
                new Masker.Replacement(8, 11, "<EMAIL_2>")));

        assertThat(masked).isEqualTo("a <SECRET_1> c <EMAIL_2> e");
    }
}
