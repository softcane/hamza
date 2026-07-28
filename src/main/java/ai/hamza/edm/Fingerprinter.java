package ai.hamza.edm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.Normalizer;
import java.util.Locale;

/**
 * Value normalization + salted one-way fingerprinting for Exact Data Match.
 *
 * <p>Both sides of the match — the in-boundary indexer ({@code scripts/edm-index.py})
 * and the Gate's scan path — MUST apply byte-identical normalization and hashing, or
 * membership silently never matches. Any change here is a wire-format change: bump both
 * implementations together and re-index.
 *
 * <p>Fingerprint = first 8 bytes (big-endian long) of HMAC-SHA256(salt, normalized
 * value). 64 bits keeps 10^8-value registries compact; a rare collision can only cause
 * a false positive, which the distinct-match block threshold absorbs.
 */
public final class Fingerprinter {

    /** Normalized values shorter than this are dropped — too common to be evidence. */
    public static final int MIN_VALUE_LENGTH = 6;
    private static final String COLLISION_GUARD_DOMAIN =
            "hamza-full-fingerprint-collision-guard/v1\n";

    private Fingerprinter() {
    }

    /**
     * Canonical form of a value before hashing: Unicode NFC, trimmed, lower-cased;
     * digit-heavy values (phone/card/account numbers) keep digits only so formatting
     * differences ("4111-1111", "4111 1111") cannot defeat the match.
     */
    public static String normalize(String value) {
        if (value == null) {
            return "";
        }
        String norm = Normalizer.normalize(value, Normalizer.Form.NFC).trim().toLowerCase(Locale.ROOT);
        if (norm.matches("[0-9\\s()+\\-.]{6,}")) {
            norm = norm.replaceAll("[^0-9]", "");
        }
        return norm;
    }

    /** True when the normalized value is substantial enough to fingerprint at all. */
    public static boolean strongEnough(String normalized) {
        return normalized != null && normalized.length() >= MIN_VALUE_LENGTH;
    }

    /** First 8 bytes of HMAC-SHA256(salt, normalized), as a big-endian long. */
    public static long fingerprint(byte[] salt, String normalized) {
        byte[] digest = hmac(salt, normalized);
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (digest[i] & 0xFF);
        }
        return v;
    }

    /** Complete HMAC-SHA-256 Fingerprint for a typed Registry v2 value. */
    public static FullFingerprint fullFingerprint(byte[] salt, String normalized) {
        return FullFingerprint.fromDigest(hmac(salt, normalized));
    }

    /**
     * Independent one-way identity used only to detect an injected or cryptographic
     * full-Fingerprint collision without retaining the normalized source value.
     */
    static FullFingerprint collisionGuardFingerprint(byte[] salt, String normalized) {
        return FullFingerprint.fromDigest(hmac(salt, COLLISION_GUARD_DOMAIN + normalized));
    }

    private static byte[] hmac(byte[] salt, String normalized) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(salt, "HmacSHA256"));
            return mac.doFinal(normalized.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
