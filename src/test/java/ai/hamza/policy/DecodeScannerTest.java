package ai.hamza.policy;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class DecodeScannerTest {

    @Test
    void nonUtf8Base64SegmentIsNotRescannedAsReplacementText() {
        AtomicInteger rescans = new AtomicInteger();
        DecodeScanner scanner = new DecodeScanner(decoded -> {
            rescans.incrementAndGet();
            return List.of(new SecretDetector.Match("sentinel", 0, decoded.length()));
        });

        byte[] invalidUtf8 = new byte[24];
        Arrays.fill(invalidUtf8, (byte) 0xff);
        String encoded = Base64.getEncoder().encodeToString(invalidUtf8);

        assertThat(scanner.scanEncoded(encoded)).isEmpty();
        assertThat(rescans).hasValue(0);
    }

    @Test
    void nonUtf8PercentEncodedSegmentIsNotRescannedAsReplacementText() {
        AtomicInteger rescans = new AtomicInteger();
        DecodeScanner scanner = new DecodeScanner(decoded -> {
            rescans.incrementAndGet();
            return List.of(new SecretDetector.Match("sentinel", 0, decoded.length()));
        });

        assertThat(scanner.scanEncoded("%FF%FF%FF%FF%FF%FF%FF")).isEmpty();
        assertThat(rescans).hasValue(0);
    }

    @Test
    void lowDiversityBase64LikeFillerIsNotDecoded() {
        AtomicInteger rescans = new AtomicInteger();
        DecodeScanner scanner = new DecodeScanner(decoded -> {
            rescans.incrementAndGet();
            return List.of(new SecretDetector.Match("sentinel", 0, decoded.length()));
        });

        assertThat(scanner.scanEncoded("x".repeat(100_000))).isEmpty();
        assertThat(rescans).hasValue(0);
    }
}
