package ai.hamza.edm;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Comparator;
import java.util.Map;

/** Canonical Registry v2 byte form shared with {@code scripts/edm-index.py}. */
public final class RegistryCanonicalizer {

    private RegistryCanonicalizer() {
    }

    public static String versionDigest(String registry, byte[] salt, int blockThreshold,
                                       RegistryRecipe recipe,
                                       Map<String, TypedRegistry.Field> fields) {
        StringBuilder canonical = new StringBuilder();
        canonical.append("schemaVersion=2\n");
        canonical.append("registry=").append(registry).append('\n');
        canonical.append("salt=").append(Base64.getEncoder().encodeToString(salt)).append('\n');
        canonical.append("blockThreshold=").append(blockThreshold).append('\n');
        canonical.append("recipe=").append(recipe.id()).append(':').append(recipe.version()).append('\n');
        fields.values().stream()
                .sorted(Comparator.comparing(TypedRegistry.Field::id))
                .forEach(field -> {
                    canonical.append("field=").append(field.id()).append(':')
                            .append(field.kind().name()).append('\n');
                    field.fingerprints().stream().sorted().forEach(fingerprint ->
                            canonical.append("fingerprint=").append(fingerprint.toHex()).append('\n'));
                });
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(64);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >>> 4) & 0x0f, 16));
                hex.append(Character.forDigit(b & 0x0f, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
