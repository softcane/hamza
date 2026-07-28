package ai.hamza.extproc;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects that a body carries a substantial newly-encoded, high-entropy segment — the
 * base64 / URL-encoded blob a coached session would use to smuggle the same blocked data
 * past exact-match detection. Content-free: it returns only a boolean and never
 * decodes, retains, or logs the segment.
 *
 * <p>Deliberately narrow to keep false positives near zero: a run must be long AND
 * high-entropy (per-character Shannon entropy over a threshold), which natural-language
 * JSON text, ids, and short tokens do not reach. It reuses the same base64/URL-encoded
 * segment shapes the decode scanner already recognises.
 */
@Component
public class ReEncodedContentDetector {

    /** Minimum run length worth treating as a re-encoded blob (short tokens are ignored). */
    static final int MIN_RUN = 48;
    /** Per-character Shannon entropy (bits) above which a long run is "high-entropy". */
    static final double MIN_ENTROPY_BITS = 3.6;
    /** Bound the scan so a huge buffered body cannot dominate the hot path. */
    private static final int MAX_SCAN_CHARS = 512 * 1024;
    private static final int MAX_RUNS = 256;

    private static final Pattern ENCODED_RUN = Pattern.compile(
            "[A-Za-z0-9+/]{" + MIN_RUN + ",}={0,2}"        // standard base64
                    + "|[A-Za-z0-9_-]{" + MIN_RUN + ",}={0,2}"  // url-safe base64
                    + "|(?:%[0-9A-Fa-f]{2}){" + (MIN_RUN / 3) + ",}"); // percent-encoded

    /** True if {@code body} contains at least one long, high-entropy encoded run. */
    boolean looksReEncoded(byte[] body) {
        if (body == null || body.length < MIN_RUN) {
            return false;
        }
        String text = new String(body, 0, Math.min(body.length, MAX_SCAN_CHARS), StandardCharsets.UTF_8);
        Matcher m = ENCODED_RUN.matcher(text);
        int runs = 0;
        while (m.find() && runs < MAX_RUNS) {
            runs++;
            String run = m.group();
            if (run.length() < MIN_RUN) {
                continue;
            }
            // A long percent-encoded run is structurally suspicious on its own (its '%'
            // repetition holds entropy below the base64 bar); a base64-style run must clear
            // the high-entropy bar so ids and natural text do not trip it.
            if (run.indexOf('%') >= 0 || shannonBits(run) >= MIN_ENTROPY_BITS) {
                return true;
            }
        }
        return false;
    }

    /** Shannon entropy in bits per character (0..~6 for base64 alphabets). */
    private static double shannonBits(String s) {
        int[] counts = new int[128];
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 128) {
                counts[c]++;
                n++;
            }
        }
        if (n == 0) {
            return 0;
        }
        double bits = 0;
        for (int count : counts) {
            if (count > 0) {
                double p = (double) count / n;
                bits -= p * (Math.log(p) / Math.log(2));
            }
        }
        return bits;
    }
}
