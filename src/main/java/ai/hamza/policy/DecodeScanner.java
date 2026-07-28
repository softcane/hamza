package ai.hamza.policy;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Decodes base64/URL-encoded segments of an Egress body and re-scans the decoded bytes
 * for secrets. Agents routinely embed
 * base64 blobs, so a secret is caught even when it is one (or several) decode levels
 * deep.
 *
 * <p>A finding inside an encoded segment is reported against the <strong>whole encoded
 * segment's span</strong> in the original text and flagged {@code decoded=true}, so the
 * policy layer withholds masking (FLAG/BLOCK only) — the exact offset inside a decoded
 * blob does not map back to a safely-replaceable span in the original body.
 *
 * <p><strong>Bounded by construction.</strong> Recursion depth, segments inspected per
 * level, individual segment size, and total decode operations are all capped, so a
 * nested or oversized encoding ("decode bomb") cannot blow the hot path. This is the one
 * new unbounded-looking construct in Phase 3 and is covered by a timeout test.
 */
final class DecodeScanner {

    private static final int MAX_DEPTH = 5;
    private static final int MAX_SEGMENTS_PER_LEVEL = 64;
    private static final int MIN_SEGMENT_LEN = 20;
    private static final int MAX_SEGMENT_LEN = 256 * 1024;
    private static final int MAX_TOTAL_DECODES = 512;
    private static final double MIN_PRINTABLE_RATIO = 0.85;

    /** Standard and URL-safe base64 runs long enough to plausibly carry a secret. */
    private static final Pattern BASE64_SEGMENT =
            Pattern.compile("[A-Za-z0-9+/]{20,}={0,2}|[A-Za-z0-9_-]{20,}={0,2}");
    /** Percent-encoded runs (URL encoding); at least a few triplets to be worth decoding. */
    private static final Pattern URL_ENCODED_SEGMENT =
            Pattern.compile("(?:%[0-9A-Fa-f]{2}){3,}[!#-;=?-~]*");

    private final Function<String, List<SecretDetector.Match>> scan;

    DecodeScanner(Function<String, List<SecretDetector.Match>> scan) {
        this.scan = scan;
    }

    /** Decode-and-rescan {@code text}; returns matches found only inside encoded segments. */
    List<SecretDetector.Match> scanEncoded(String text) {
        List<SecretDetector.Match> out = new ArrayList<>();
        Set<String> emitted = new LinkedHashSet<>();
        recurse(text, 0, -1, -1, out, emitted, new int[]{MAX_TOTAL_DECODES});
        return out;
    }

    private void recurse(String text, int depth, int envStart, int envEnd,
                         List<SecretDetector.Match> out, Set<String> emitted, int[] budget) {
        if (depth >= MAX_DEPTH || budget[0] <= 0 || text.isEmpty()) {
            return;
        }
        scanKind(BASE64_SEGMENT.matcher(text), depth, envStart, envEnd, out, emitted, budget, true);
        scanKind(URL_ENCODED_SEGMENT.matcher(text), depth, envStart, envEnd, out, emitted, budget, false);
    }

    private void scanKind(Matcher matcher, int depth, int envStart, int envEnd,
                          List<SecretDetector.Match> out, Set<String> emitted, int[] budget,
                          boolean base64) {
        int seen = 0;
        while (matcher.find() && seen < MAX_SEGMENTS_PER_LEVEL && budget[0] > 0) {
            seen++;
            String raw = matcher.group();
            if (raw.length() < MIN_SEGMENT_LEN || raw.length() > MAX_SEGMENT_LEN) {
                continue;
            }
            if (base64 && !plausibleBase64(raw)) {
                continue;
            }
            String decoded = base64 ? tryBase64(raw) : tryUrl(raw);
            if (decoded == null || decoded.isEmpty() || decoded.equals(raw)
                    || !mostlyPrintable(decoded)) {
                continue;
            }
            budget[0]--;
            // At the top level the envelope IS this segment; deeper levels keep pointing
            // at the top-level segment so every decoded finding maps to a real span.
            int es = depth == 0 ? matcher.start() : envStart;
            int ee = depth == 0 ? matcher.end() : envEnd;
            for (SecretDetector.Match match : scan.apply(decoded)) {
                if (emitted.add(match.rule() + ':' + es + ':' + ee)) {
                    out.add(new SecretDetector.Match(match.rule(), es, ee, true));
                }
            }
            recurse(decoded, depth + 1, es, ee, out, emitted, budget);
        }
    }

    private static String tryBase64(String raw) {
        String decoded = decodeBase64(raw, false);
        if (decoded != null) {
            return decoded;
        }
        return decodeBase64(raw, true);
    }

    private static boolean plausibleBase64(String raw) {
        boolean[] seen = new boolean[128];
        int distinct = 0;
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '=') {
                continue;
            }
            if (c >= 128) {
                return true;
            }
            if (!seen[c]) {
                seen[c] = true;
                distinct++;
                if (distinct >= 8) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String decodeBase64(String raw, boolean urlSafe) {
        String normalized = normalizeBase64(raw);
        if (normalized == null) {
            return null;
        }
        try {
            byte[] bytes = (urlSafe ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(normalized);
            if (bytes.length == 0) {
                return null;
            }
            return strictUtf8(bytes);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Re-pad a base64 run to a valid length without dropping data characters. */
    private static String normalizeBase64(String raw) {
        int end = raw.length();
        while (end > 0 && raw.charAt(end - 1) == '=') {
            end--;
        }
        String core = raw.substring(0, end);
        return switch (core.length() % 4) {
            case 0 -> core;
            case 2 -> core + "==";
            case 3 -> core + "=";
            default -> null; // length %4 == 1 is not valid base64
        };
    }

    private static String tryUrl(String raw) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '%' && i + 2 < raw.length()) {
                int hi = Character.digit(raw.charAt(i + 1), 16);
                int lo = Character.digit(raw.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.write((hi << 4) + lo);
                    i += 2;
                    continue;
                }
            }
            out.write((byte) c);
        }
        return strictUtf8(out.toByteArray());
    }

    private static String strictUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException e) {
            return null;
        }
    }

    private static boolean mostlyPrintable(String s) {
        int printable = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\uFFFD'
                    && (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) || c >= 0xa0)) {
                printable++;
            }
        }
        return !s.isEmpty() && (double) printable / s.length() >= MIN_PRINTABLE_RATIO;
    }
}
