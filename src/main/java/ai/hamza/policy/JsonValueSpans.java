package ai.hamza.policy;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;
import java.util.Optional;

/**
 * The JSON string <em>values</em> of one body exactly as they sit on the wire, and the
 * offsets inside them where a Placeholder may be spliced.
 *
 * <p>The standard route masks the raw body by char offset, but a detector span is not
 * JSON-aware: Presidio's URL recognizer, for instance, runs to the next whitespace, and
 * compact JSON has none — so one span can swallow {@code ","key":"} and everything after
 * it. A body spliced like that is no longer JSON and the Provider rejects the whole Turn.
 *
 * <p>So every span is first {@linkplain #clamp clamped} to the one string value it starts
 * in. A clamped span can never cross a quote, an escape, a surrogate pair, or structural
 * punctuation, which makes "valid JSON in, valid JSON out" a property of the arithmetic
 * rather than a hope. Field names are deliberately not clampable targets: rewriting a key
 * would still parse but would no longer be the Provider's request.
 *
 * <p>Instances are immutable and content-free apart from the offsets themselves.
 */
final class JsonValueSpans {

    private static final JsonFactory FACTORY = new JsonFactory();

    /** Content start (just after the opening quote) of each string value, ascending. */
    private final int[] starts;
    /** Content end (the closing quote) of each string value, aligned with {@link #starts}. */
    private final int[] ends;
    /** Every offset a replacement may begin or end at, inside those values. */
    private final BitSet cuts;

    private JsonValueSpans(int[] starts, int[] ends, BitSet cuts) {
        this.starts = starts;
        this.ends = ends;
        this.cuts = cuts;
    }

    /** One span already clamped to a single JSON string value. */
    record Span(int start, int end) {
    }

    /**
     * Map the string values of {@code text}, or empty when {@code text} is not JSON —
     * in which case the caller owns the wire shape and masks the raw text unchanged.
     */
    static Optional<JsonValueSpans> of(String text) {
        if (text == null || text.isEmpty() || !parses(text)) {
            return Optional.empty();
        }
        List<int[]> values = new ArrayList<>();
        BitSet cuts = new BitSet(text.length() + 1);
        int index = 0;
        while (index < text.length()) {
            if (text.charAt(index) != '"') {
                index++;
                continue;
            }
            int content = index + 1;
            int close = closingQuote(text, content);
            if (close < 0) {
                return Optional.empty(); // unterminated: refuse to guess at the shape
            }
            if (!isFieldName(text, close)) {
                values.add(new int[] {content, close});
                markCuts(text, content, close, cuts);
            }
            index = close + 1;
        }
        // A JSON body with no string value at all still maps: every span then clamps to
        // nothing, which is the right answer — there is no value here to replace.
        int[] starts = new int[values.size()];
        int[] ends = new int[values.size()];
        for (int i = 0; i < values.size(); i++) {
            starts[i] = values.get(i)[0];
            ends[i] = values.get(i)[1];
        }
        return Optional.of(new JsonValueSpans(starts, ends, cuts));
    }

    /** Does {@code text} parse as JSON? The proof a masked body may be egressed. */
    static boolean parses(String text) {
        if (text == null || text.isBlank()) {
            return false;
        }
        try (JsonParser parser = FACTORY.createParser(text)) {
            while (parser.nextToken() != null) {
                // Structure only: nothing is read from the values.
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Clamp {@code [start, end)} to the string value that holds it. A span that starts
     * outside every value adopts the first value it reaches; a span that covers no value
     * at all — a field name, a number, pure punctuation — has no safe replacement and
     * returns empty.
     */
    Optional<Span> clamp(int start, int end) {
        if (start < 0 || end <= start) {
            return Optional.empty();
        }
        int value = valueFor(start, end);
        if (value < 0) {
            return Optional.empty();
        }
        int from = cuts.nextSetBit(Math.max(start, starts[value]));
        if (from < 0 || from >= ends[value]) {
            return Optional.empty();
        }
        int to = cuts.previousSetBit(Math.min(end, ends[value]));
        if (to <= from) {
            return Optional.empty();
        }
        return Optional.of(new Span(from, to));
    }

    /** Index of the string value covering {@code start}, else the next one inside the span. */
    private int valueFor(int start, int end) {
        int found = Arrays.binarySearch(starts, start);
        if (found >= 0) {
            return found;
        }
        int next = -found - 1;              // first value that begins after start
        int covering = next - 1;
        if (covering >= 0 && start < ends[covering]) {
            return covering;
        }
        return next < starts.length && starts[next] < end ? next : -1;
    }

    /** Offset of the quote closing the string whose content begins at {@code content}. */
    private static int closingQuote(String text, int content) {
        int index = content;
        while (index < text.length()) {
            char c = text.charAt(index);
            if (c == '\\') {
                index += 2;                 // an escape never ends the string
            } else if (c == '"') {
                return index;
            } else {
                index++;
            }
        }
        return -1;
    }

    /** A string token followed by {@code :} is a field name, not a value. */
    private static boolean isFieldName(String text, int closingQuote) {
        for (int index = closingQuote + 1; index < text.length(); index++) {
            char c = text.charAt(index);
            if (c == ':') {
                return true;
            }
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                return false;
            }
        }
        return false;
    }

    /**
     * Record every offset inside one value at which a replacement may begin or end: the
     * start of each character token, plus the end of the content. Cutting anywhere else
     * would split an escape or a surrogate pair and leave the body unparseable.
     */
    private static void markCuts(String text, int content, int close, BitSet cuts) {
        int index = content;
        while (index < close) {
            cuts.set(index);
            index = Math.min(close, index + tokenLength(text, index, close));
        }
        cuts.set(close);
    }

    private static int tokenLength(String text, int index, int close) {
        char c = text.charAt(index);
        if (c == '\\') {
            if (index + 1 < close && text.charAt(index + 1) == 'u') {
                // An escaped surrogate pair is one character and is never split.
                return index + 12 <= close && isEscapedHighSurrogate(text, index)
                        && isEscapedLowSurrogate(text, index + 6) ? 12 : 6;
            }
            return 2;
        }
        if (Character.isHighSurrogate(c) && index + 1 < close
                && Character.isLowSurrogate(text.charAt(index + 1))) {
            return 2;
        }
        return 1;
    }

    private static boolean isEscapedHighSurrogate(String text, int index) {
        return Character.isHighSurrogate(escapedChar(text, index));
    }

    private static boolean isEscapedLowSurrogate(String text, int index) {
        return text.charAt(index) == '\\' && text.charAt(index + 1) == 'u'
                && Character.isLowSurrogate(escapedChar(text, index));
    }

    private static char escapedChar(String text, int index) {
        try {
            return (char) Integer.parseInt(text, index + 2, index + 6, 16);
        } catch (RuntimeException e) {
            return '\0';
        }
    }
}
