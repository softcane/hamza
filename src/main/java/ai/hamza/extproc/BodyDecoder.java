package ai.hamza.extproc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * Decodes a compressed request body before inspection. A gzipped body fed
 * straight to the regex engine turns detection into fiction; decode-before-inspect is
 * an invariant, and an undecodable encoded body must surface as an
 * {@code opaque-content} Finding, never a silent pass.
 *
 * <p>Decoding is bounded: a body that inflates past {@code maxDecodedBytes} is treated
 * as opaque rather than buffered without limit (zip-bomb resistance).
 */
final class BodyDecoder {

    private BodyDecoder() {
    }

    /** True for encodings this decoder can see through (gzip/x-gzip, zlib deflate). */
    static boolean isSupported(String contentEncoding) {
        String enc = normalize(contentEncoding);
        return enc.equals("gzip") || enc.equals("x-gzip") || enc.equals("deflate");
    }

    /** True when the encoding is present, not identity, and not decodable here. */
    static boolean isOpaque(String contentEncoding) {
        String enc = normalize(contentEncoding);
        return !enc.isEmpty() && !enc.equals("identity") && !isSupported(contentEncoding);
    }

    /**
     * True for any non-identity encoding. Oversize bodies (prefix or streamed) cannot be
     * decoded incrementally yet, so an encoded oversize Turn is opaque regardless of
     * whether the codec is otherwise supported.
     */
    static boolean isEncoded(String contentEncoding) {
        String enc = normalize(contentEncoding);
        return !enc.isEmpty() && !enc.equals("identity");
    }

    /**
     * Decode {@code body} per {@code contentEncoding}, up to {@code maxDecodedBytes}.
     * Empty when the encoding is unsupported, the stream is corrupt, or the decoded
     * size exceeds the bound — callers must treat that as opaque content.
     */
    static Optional<byte[]> decode(byte[] body, String contentEncoding, int maxDecodedBytes) {
        if (body == null || body.length == 0 || !isSupported(contentEncoding)) {
            return Optional.empty();
        }
        String enc = normalize(contentEncoding);
        try (InputStream in = enc.equals("deflate")
                ? new InflaterInputStream(new ByteArrayInputStream(body))
                : new GZIPInputStream(new ByteArrayInputStream(body))) {
            byte[] decoded = in.readNBytes(maxDecodedBytes);
            if (in.read() != -1) {
                return Optional.empty(); // inflates past the bound: opaque, not unbounded
            }
            return Optional.of(decoded);
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    private static String normalize(String contentEncoding) {
        return contentEncoding == null ? "" : contentEncoding.trim().toLowerCase(Locale.ROOT);
    }
}
