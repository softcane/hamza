package ai.hamza.edm;

import ai.hamza.config.HamzaProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Atomic in-memory snapshot of legacy Registry v1 and typed Registry v2 files. A
 * malformed v2 file is rejected as a whole; no partial field set can become active.
 */
@Component
public class RegistryStore {

    private static final Logger log = LoggerFactory.getLogger(RegistryStore.class);
    private static final Set<String> V2_ROOT_FIELDS = Set.of(
            "schemaVersion", "registry", "version", "salt", "blockThreshold", "recipe", "fields");
    private static final Set<String> RECIPE_FIELDS = Set.of("id", "version");
    private static final Set<String> TYPED_FIELD_FIELDS = Set.of("id", "kind", "fingerprints");

    private final Path dir;
    private final int maxContinuationEntries;
    private volatile Snapshot snapshot;

    @Autowired
    public RegistryStore(HamzaProperties properties) {
        this(properties.edm().enabled() ? Path.of(properties.edm().registryDir()) : null,
                properties.edm().maxContinuationEntries());
    }

    RegistryStore(Path dir) {
        this(dir, HamzaProperties.DEFAULT_EDM_MAX_CONTINUATION_ENTRIES);
    }

    RegistryStore(Path dir, int maxContinuationEntries) {
        this.dir = dir;
        this.maxContinuationEntries = maxContinuationEntries > 0 ? maxContinuationEntries
                : HamzaProperties.DEFAULT_EDM_MAX_CONTINUATION_ENTRIES;
        this.snapshot = dir == null ? Snapshot.EMPTY : load(dir, this.maxContinuationEntries);
    }

    /** Legacy v1 Registries; these remain detection-compatible and continuation-ineligible. */
    public List<FingerprintRegistry> registries() {
        return snapshot.legacy();
    }

    /** Strictly validated continuation-capable Registry v2 snapshots. */
    public List<TypedRegistry> typedRegistries() {
        return snapshot.typed();
    }

    public Optional<Path> registryDir() {
        return Optional.ofNullable(dir);
    }

    public boolean isEmpty() {
        return snapshot.legacy().isEmpty() && snapshot.typed().isEmpty();
    }

    public synchronized void reload() {
        snapshot = dir == null ? Snapshot.EMPTY : load(dir, maxContinuationEntries);
    }

    private static Snapshot load(Path dir, int maxContinuationEntries) {
        if (!Files.isDirectory(dir)) {
            log.warn("EDM registry dir {} does not exist; EDM disabled", dir);
            return Snapshot.EMPTY;
        }
        ObjectMapper mapper = new ObjectMapper();
        List<FingerprintRegistry> legacy = new ArrayList<>();
        List<TypedRegistry> typed = new ArrayList<>();
        try (Stream<Path> files = Files.list(dir)) {
            for (Path file : files.filter(path -> path.toString().endsWith(".json")).sorted().toList()) {
                try {
                    JsonNode root = mapper.readTree(Files.readAllBytes(file));
                    if (root.has("schemaVersion")) {
                        TypedRegistry registry = parseV2(root, maxContinuationEntries);
                        typed.add(registry);
                        log.info("EDM typed registry loaded: name={} fields={} fingerprints={}",
                                registry.id(), registry.fields().size(), registry.fingerprintCount());
                    } else {
                        FingerprintRegistry registry = parseV1(root);
                        legacy.add(registry);
                        log.info("EDM registry loaded: name={} fingerprints={}",
                                registry.name(), registry.fingerprints().size());
                    }
                } catch (Exception e) {
                    log.warn("EDM registry file {} failed to load: {}",
                            file.getFileName(), boundedReason(e));
                }
            }
        } catch (IOException e) {
            log.warn("EDM registry dir {} unreadable: {}", dir, e.getClass().getSimpleName());
        }
        return new Snapshot(List.copyOf(legacy), List.copyOf(typed));
    }

    private static FingerprintRegistry parseV1(JsonNode root) {
        if (root == null || !root.isObject()) {
            throw invalid("legacy-shape");
        }
        String name = requiredText(root, "registry");
        byte[] salt = decodeSalt(requiredText(root, "salt"), false);
        JsonNode entries = root.path("fingerprints");
        if (!entries.isArray()) {
            throw invalid("legacy-fingerprints");
        }
        Set<Long> fingerprints = new HashSet<>();
        for (JsonNode entry : entries) {
            String hex = entry.asText("");
            if (!hex.matches("[0-9a-f]{16}")) {
                throw invalid("legacy-fingerprint");
            }
            fingerprints.add(Long.parseUnsignedLong(hex, 16));
        }
        if (name.isBlank() || salt.length == 0) {
            throw invalid("legacy-incomplete");
        }
        return new FingerprintRegistry(name, salt, Set.copyOf(fingerprints));
    }

    private static TypedRegistry parseV2(JsonNode root, int maxContinuationEntries) {
        requireExactFields(root, V2_ROOT_FIELDS);
        if (!root.path("schemaVersion").isIntegralNumber()
                || root.path("schemaVersion").asInt() != TypedRegistry.SCHEMA_VERSION) {
            throw invalid("schema-version");
        }
        String registry = requiredText(root, "registry");
        String version = requiredText(root, "version");
        byte[] salt = decodeSalt(requiredText(root, "salt"), true);
        JsonNode thresholdNode = root.path("blockThreshold");
        if (!thresholdNode.isIntegralNumber() || thresholdNode.asInt() != 1) {
            throw invalid("block-threshold");
        }

        JsonNode recipeNode = root.path("recipe");
        requireExactFields(recipeNode, RECIPE_FIELDS);
        RegistryRecipe recipe = new RegistryRecipe(requiredText(recipeNode, "id"),
                requiredPositiveInt(recipeNode, "version"));
        if (!recipe.equals(new RegistryRecipe("synthetic-email", 1))) {
            throw invalid("recipe");
        }

        JsonNode fieldNodes = root.path("fields");
        if (!fieldNodes.isArray() || fieldNodes.isEmpty()) {
            throw invalid("fields");
        }
        Map<String, TypedRegistry.Field> fields = new LinkedHashMap<>();
        int entryCount = 0;
        for (JsonNode fieldNode : fieldNodes) {
            requireExactFields(fieldNode, TYPED_FIELD_FIELDS);
            String id = requiredText(fieldNode, "id");
            ReplacementKind kind;
            try {
                kind = ReplacementKind.valueOf(requiredText(fieldNode, "kind"));
            } catch (IllegalArgumentException e) {
                throw invalid("replacement-kind");
            }
            JsonNode fingerprintNodes = fieldNode.path("fingerprints");
            if (!fingerprintNodes.isArray() || fingerprintNodes.isEmpty()) {
                throw invalid("fingerprints");
            }
            Set<FullFingerprint> fingerprints = new HashSet<>();
            for (JsonNode fingerprintNode : fingerprintNodes) {
                if (!fingerprintNode.isTextual()) {
                    throw invalid("fingerprint");
                }
                FullFingerprint fingerprint = FullFingerprint.parseHex(fingerprintNode.textValue());
                if (!fingerprints.add(fingerprint)) {
                    throw invalid("duplicate-fingerprint");
                }
                entryCount = Math.addExact(entryCount, 1);
                if (entryCount > maxContinuationEntries) {
                    throw invalid("registry-entry-limit");
                }
            }
            TypedRegistry.Field field = new TypedRegistry.Field(id, kind, fingerprints);
            if (fields.putIfAbsent(id, field) != null) {
                throw invalid("duplicate-field");
            }
        }
        return TypedRegistry.load(registry, version, salt, thresholdNode.asInt(), recipe, fields);
    }

    private static String requiredText(JsonNode root, String field) {
        JsonNode node = root.path(field);
        if (!node.isTextual() || node.textValue().isBlank()) {
            throw invalid(field);
        }
        return node.textValue();
    }

    private static int requiredPositiveInt(JsonNode root, String field) {
        JsonNode node = root.path(field);
        if (!node.isIntegralNumber() || node.asInt() <= 0) {
            throw invalid(field);
        }
        return node.asInt();
    }

    private static byte[] decodeSalt(String encoded, boolean exactWidth) {
        try {
            byte[] salt = Base64.getDecoder().decode(encoded);
            if ((exactWidth && salt.length != 32) || (!exactWidth && salt.length == 0)) {
                throw invalid("salt-width");
            }
            return salt;
        } catch (IllegalArgumentException e) {
            throw invalid("salt");
        }
    }

    private static void requireExactFields(JsonNode node, Set<String> expected) {
        if (node == null || !node.isObject()) {
            throw invalid("object-shape");
        }
        Set<String> actual = new HashSet<>();
        node.fieldNames().forEachRemaining(actual::add);
        if (!actual.equals(expected)) {
            throw invalid("unknown-or-missing-field");
        }
    }

    private static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException(reason);
    }

    private static String boundedReason(Exception e) {
        String reason = e.getMessage();
        if (reason == null || !reason.matches("[a-z0-9-]{1,64}")) {
            return e.getClass().getSimpleName();
        }
        return reason;
    }

    private record Snapshot(List<FingerprintRegistry> legacy, List<TypedRegistry> typed) {
        private static final Snapshot EMPTY = new Snapshot(List.of(), List.of());
    }
}
