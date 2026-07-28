package ai.hamza.edm;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Immutable continuation-capable Registry v2. It stores only a per-Registry salt,
 * typed full-width Fingerprints, bounded metadata, and its canonical version digest.
 */
public final class TypedRegistry {

    public static final int SCHEMA_VERSION = 2;
    private static final Pattern REGISTRY_ID = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");
    private static final Pattern FIELD_ID = Pattern.compile("[a-z0-9][a-z0-9_-]{0,62}");
    private static final Pattern VERSION = Pattern.compile("[0-9a-f]{64}");

    private final String id;
    private final String version;
    private final byte[] salt;
    private final int blockThreshold;
    private final RegistryRecipe recipe;
    private final Map<String, Field> fields;

    private TypedRegistry(String id, String version, byte[] salt, int blockThreshold,
                          RegistryRecipe recipe, Map<String, Field> fields) {
        validate(id, version, salt, blockThreshold, recipe, fields);
        this.id = id;
        this.version = version;
        this.salt = salt.clone();
        this.blockThreshold = blockThreshold;
        this.recipe = recipe;
        this.fields = immutableFields(fields);
    }

    public static TypedRegistry create(String id, byte[] salt, int blockThreshold,
                                       RegistryRecipe recipe, Map<String, Field> fields) {
        Map<String, Field> safeFields = immutableFields(fields);
        String version = RegistryCanonicalizer.versionDigest(
                id, checkedSalt(salt), blockThreshold, recipe, safeFields);
        return new TypedRegistry(id, version, salt, blockThreshold, recipe, safeFields);
    }

    public static TypedRegistry load(String id, String version, byte[] salt, int blockThreshold,
                                     RegistryRecipe recipe, Map<String, Field> fields) {
        TypedRegistry loaded = new TypedRegistry(id, version, salt, blockThreshold, recipe, fields);
        String expected = RegistryCanonicalizer.versionDigest(
                loaded.id, loaded.salt, loaded.blockThreshold, loaded.recipe, loaded.fields);
        if (!expected.equals(version)) {
            throw new IllegalArgumentException("registry-version-mismatch");
        }
        return loaded;
    }

    public String id() {
        return id;
    }

    public String version() {
        return version;
    }

    public byte[] salt() {
        return salt.clone();
    }

    public int blockThreshold() {
        return blockThreshold;
    }

    public RegistryRecipe recipe() {
        return recipe;
    }

    public Map<String, Field> fields() {
        return fields;
    }

    public int fingerprintCount() {
        return fields.values().stream().mapToInt(field -> field.fingerprints().size()).sum();
    }

    private static byte[] checkedSalt(byte[] salt) {
        if (salt == null || salt.length != 32) {
            throw new IllegalArgumentException("registry-salt-width");
        }
        return salt;
    }

    private static Map<String, Field> immutableFields(Map<String, Field> fields) {
        if (fields == null || fields.isEmpty()) {
            throw new IllegalArgumentException("registry-fields-required");
        }
        Map<String, Field> copy = new LinkedHashMap<>();
        fields.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> {
            Field field = Objects.requireNonNull(entry.getValue(), "registry-field");
            if (!entry.getKey().equals(field.id()) || copy.put(entry.getKey(), field) != null) {
                throw new IllegalArgumentException("invalid-registry-field");
            }
        });
        return Map.copyOf(copy);
    }

    private static void validate(String id, String version, byte[] salt, int blockThreshold,
                                 RegistryRecipe recipe, Map<String, Field> fields) {
        if (id == null || !REGISTRY_ID.matcher(id).matches()) {
            throw new IllegalArgumentException("invalid-registry-name");
        }
        if (version == null || !VERSION.matcher(version).matches()) {
            throw new IllegalArgumentException("invalid-registry-version");
        }
        checkedSalt(salt);
        if (blockThreshold <= 0) {
            throw new IllegalArgumentException("invalid-registry-threshold");
        }
        Objects.requireNonNull(recipe, "registry-recipe");
        immutableFields(fields);
    }

    public record Field(String id, ReplacementKind kind, Set<FullFingerprint> fingerprints) {
        public Field {
            if (id == null || !FIELD_ID.matcher(id).matches() || kind == null
                    || fingerprints == null || fingerprints.isEmpty()
                    || fingerprints.stream().anyMatch(Objects::isNull)) {
                throw new IllegalArgumentException("invalid-registry-field");
            }
            fingerprints = Set.copyOf(fingerprints);
        }
    }
}
