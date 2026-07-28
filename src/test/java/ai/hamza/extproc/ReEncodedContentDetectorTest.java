package ai.hamza.extproc;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Re-encoded-content detection: fire on a long, high-entropy base64 / encoded
 * blob (the evasion escape), stay quiet on ordinary JSON, ids, and short tokens.
 */
class ReEncodedContentDetectorTest {

    private final ReEncodedContentDetector detector = new ReEncodedContentDetector();

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void ordinaryJsonIsNotFlagged() {
        assertThat(detector.looksReEncoded(utf8(
                "{\"model\":\"gpt-5-codex\",\"input\":\"list the domains for these customers and flag dupes\"}")))
                .isFalse();
    }

    @Test
    void longHighEntropyBase64BlobIsFlagged() {
        byte[] random = new byte[256];
        for (int i = 0; i < random.length; i++) {
            random[i] = (byte) ((i * 197 + 31) ^ (i << 3)); // deterministic, spread across the alphabet
        }
        String blob = Base64.getEncoder().encodeToString(random);
        assertThat(detector.looksReEncoded(utf8("{\"input\":\"" + blob + "\"}"))).isTrue();
    }

    @Test
    void percentEncodedRunIsFlagged() {
        StringBuilder pct = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            pct.append('%').append(String.format("%02X", (i * 7 + 3) & 0xFF));
        }
        assertThat(detector.looksReEncoded(utf8(pct.toString()))).isTrue();
    }

    @Test
    void shortTokenIsNotFlagged() {
        assertThat(detector.looksReEncoded(utf8("{\"id\":\"abc123DEF456\"}"))).isFalse();
    }

    @Test
    void lowEntropyLongRunIsNotFlagged() {
        // A long run of a few repeated characters is long but low-entropy — not a payload.
        assertThat(detector.looksReEncoded(utf8("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")))
                .isFalse();
    }

    @Test
    void nullAndTinyBodiesAreSafe() {
        assertThat(detector.looksReEncoded(null)).isFalse();
        assertThat(detector.looksReEncoded(utf8("hi"))).isFalse();
    }
}
