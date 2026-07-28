package ai.hamza.edm;

import java.util.Arrays;

/**
 * Immutable complete HMAC-SHA-256 Fingerprint used by continuation-capable Registry
 * versions. The digest is always exactly 32 bytes and is never exposed as a mutable
 * byte array.
 */
public final class FullFingerprint implements Comparable<FullFingerprint> {

    public static final int BYTES = 32;
    public static final int HEX_CHARS = BYTES * 2;

    private final byte[] digest;

    private FullFingerprint(byte[] digest) {
        this.digest = digest.clone();
    }

    public static FullFingerprint fromDigest(byte[] digest) {
        if (digest == null || digest.length != BYTES) {
            throw new IllegalArgumentException("full-fingerprint-width");
        }
        return new FullFingerprint(digest);
    }

    public static FullFingerprint parseHex(String hex) {
        if (hex == null || hex.length() != HEX_CHARS || !hex.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("full-fingerprint-hex");
        }
        byte[] digest = new byte[BYTES];
        for (int i = 0; i < digest.length; i++) {
            int at = i * 2;
            digest[i] = (byte) Integer.parseInt(hex, at, at + 2, 16);
        }
        return new FullFingerprint(digest);
    }

    public String toHex() {
        StringBuilder out = new StringBuilder(HEX_CHARS);
        for (byte b : digest) {
            out.append(Character.forDigit((b >>> 4) & 0x0f, 16));
            out.append(Character.forDigit(b & 0x0f, 16));
        }
        return out.toString();
    }

    @Override
    public int compareTo(FullFingerprint other) {
        return Arrays.compareUnsigned(digest, other.digest);
    }

    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof FullFingerprint that
                && Arrays.equals(digest, that.digest);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(digest);
    }

    @Override
    public String toString() {
        return "FullFingerprint[redacted]";
    }
}
