package ai.hamza.edm;

import ai.hamza.config.HamzaProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BiFunction;
import java.util.regex.Pattern;

import static ai.hamza.edm.RegistryIngestionException.Kind.BAD_REQUEST;
import static ai.hamza.edm.RegistryIngestionException.Kind.DISABLED;

/** Streams CSV values directly into legacy or typed one-way Fingerprints. */
@Service
public class RegistryIngestionService {

    private static final Logger log = LoggerFactory.getLogger(RegistryIngestionService.class);
    private static final Pattern REGISTRY_NAME = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");
    private static final int SALT_BYTES = 32;

    private final RegistryStore store;
    private final HamzaProperties properties;
    private final ObjectMapper mapper;
    private final SecureRandom random;
    private final int maxRowChars;
    private final int maxFieldChars;
    private final BiFunction<byte[], String, FullFingerprint> fullFingerprinter;

    @Autowired
    public RegistryIngestionService(RegistryStore store, HamzaProperties properties) {
        this(store, properties, new ObjectMapper(), new SecureRandom(),
                CsvStreamReader.DEFAULT_MAX_ROW_CHARS, CsvStreamReader.DEFAULT_MAX_FIELD_CHARS,
                Fingerprinter::fullFingerprint);
    }

    RegistryIngestionService(RegistryStore store, HamzaProperties properties,
                             ObjectMapper mapper, SecureRandom random,
                             int maxRowChars, int maxFieldChars) {
        this(store, properties, mapper, random, maxRowChars, maxFieldChars,
                Fingerprinter::fullFingerprint);
    }

    RegistryIngestionService(RegistryStore store, HamzaProperties properties,
                             ObjectMapper mapper, SecureRandom random,
                             int maxRowChars, int maxFieldChars,
                             BiFunction<byte[], String, FullFingerprint> fullFingerprinter) {
        this.store = store;
        this.properties = properties;
        this.mapper = mapper;
        this.random = random;
        this.maxRowChars = maxRowChars;
        this.maxFieldChars = maxFieldChars;
        this.fullFingerprinter = fullFingerprinter;
    }

    /** Existing v1 interface remains byte-for-byte compatible. */
    public RegistryIngestionReceipt ingest(String name, InputStream csv, String columns) {
        return ingest(RegistryIngestCommand.legacy(name, columns), csv);
    }

    public RegistryIngestionReceipt ingest(RegistryIngestCommand command, InputStream csv) {
        String registry = validateName(command.registry());
        Path dir = registryDir();
        try {
            Files.createDirectories(dir);
            byte[] salt = existingSalt(dir, registry).orElseGet(this::freshSalt);
            RegistryIngestionReceipt receipt = command.typed()
                    ? ingestTyped(dir, registry, salt, command, csv)
                    : ingestLegacy(dir, registry, salt, command, csv);
            store.reload();
            log.info("EDM registry ingested: name={} valuesSeen={} indexed={} droppedWeak={} distinct={} schema={}",
                    registry, receipt.valuesSeen(), receipt.indexed(), receipt.droppedWeak(),
                    receipt.distinctFingerprints(), command.typed() ? 2 : 1);
            return receipt;
        } catch (IOException e) {
            throw new UncheckedIOException("registry-ingest-io", e);
        }
    }

    private RegistryIngestionReceipt ingestLegacy(Path dir, String registry, byte[] salt,
                                                   RegistryIngestCommand command,
                                                   InputStream csv) throws IOException {
        CsvFingerprintSet set = fingerprintCsv(csv, new LinkedHashSet<>(command.columns()), salt);
        List<String> fingerprintHex = sortedHex(set.fingerprints());
        String version = versionDigest(fingerprintHex);
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("registry", registry);
        json.put("salt", Base64.getEncoder().encodeToString(salt));
        json.put("fingerprints", fingerprintHex);
        writeVersion(dir, registry, json);
        return new RegistryIngestionReceipt(registry, version, set.valuesSeen(), set.indexed(),
                set.droppedWeak(), fingerprintHex.size());
    }

    private RegistryIngestionReceipt ingestTyped(Path dir, String registry, byte[] salt,
                                                  RegistryIngestCommand command,
                                                  InputStream csv) throws IOException {
        TypedFingerprintSet set = fingerprintTypedCsv(csv, command, salt);
        Map<String, TypedRegistry.Field> fields = new LinkedHashMap<>();
        for (String fieldId : command.columns()) {
            Set<FullFingerprint> fingerprints = set.fingerprints().get(fieldId);
            if (fingerprints == null || fingerprints.isEmpty()) {
                throw bad("typed-registry-empty-field");
            }
            fields.put(fieldId, new TypedRegistry.Field(fieldId,
                    command.replacementKinds().get(fieldId), fingerprints));
        }
        TypedRegistry typed = TypedRegistry.create(registry, salt, command.blockThreshold(),
                command.recipe(), fields);
        writeVersion(dir, registry, typedJson(typed));
        return new RegistryIngestionReceipt(registry, typed.version(), set.valuesSeen(), set.indexed(),
                set.droppedWeak(), typed.fingerprintCount());
    }

    public List<RegistryStats> listRegistries() {
        Path dir = store.registryDir().orElse(null);
        if (dir == null || !Files.isDirectory(dir)) {
            return List.of();
        }
        Map<String, List<RegistryStats.RegistryVersionStats>> byRegistry = new LinkedHashMap<>();
        try (var files = Files.list(dir)) {
            for (Path file : files.filter(path -> path.toString().endsWith(".json"))
                    .sorted(Comparator.comparing(Path::toString)).toList()) {
                Optional<FileView> view = readFileView(file);
                if (view.isEmpty()) {
                    continue;
                }
                FileView value = view.get();
                byRegistry.computeIfAbsent(value.registry(), ignored -> new ArrayList<>())
                        .add(new RegistryStats.RegistryVersionStats(value.version(),
                                value.distinctFingerprints(), isCurrentFile(file, value.registry())));
            }
        } catch (IOException e) {
            throw new UncheckedIOException("registry-list-io", e);
        }
        return byRegistry.entrySet().stream()
                .map(entry -> new RegistryStats(entry.getKey(), List.copyOf(entry.getValue())))
                .toList();
    }

    public void delete(String name) {
        String registry = validateName(name);
        Path dir = registryDir();
        try {
            Files.deleteIfExists(currentPath(dir, registry));
            Files.deleteIfExists(previousPath(dir, registry));
            store.reload();
            log.info("EDM registry erased: name={}", registry);
        } catch (IOException e) {
            throw new UncheckedIOException("registry-delete-io", e);
        }
    }

    private CsvFingerprintSet fingerprintCsv(InputStream csv, Set<String> wantedColumns,
                                             byte[] salt) throws IOException {
        Set<Long> fingerprints = new LinkedHashSet<>();
        CsvScanCounts counts = scanCsv(csv, wantedColumns, (fieldId, normalized) ->
                fingerprints.add(Fingerprinter.fingerprint(salt, normalized)));
        return new CsvFingerprintSet(counts.valuesSeen(), counts.indexed(), counts.droppedWeak(),
                fingerprints);
    }

    private TypedFingerprintSet fingerprintTypedCsv(InputStream csv, RegistryIngestCommand command,
                                                     byte[] salt) throws IOException {
        Map<String, Set<FullFingerprint>> fingerprints = new LinkedHashMap<>();
        command.columns().forEach(field -> fingerprints.put(field, new LinkedHashSet<>()));
        Map<FullFingerprint, FullFingerprint> collisionGuard = new HashMap<>();
        int[] distinctEntries = {0};
        CsvScanCounts counts = scanCsv(csv, new LinkedHashSet<>(command.columns()), (fieldId, normalized) -> {
            FullFingerprint fingerprint = fullFingerprinter.apply(salt, normalized);
            FullFingerprint guard = Fingerprinter.collisionGuardFingerprint(salt, normalized);
            FullFingerprint previous = collisionGuard.putIfAbsent(fingerprint, guard);
            if (previous != null && !previous.equals(guard)) {
                throw bad("full-fingerprint-collision");
            }
            if (fingerprints.get(fieldId).add(fingerprint)) {
                distinctEntries[0]++;
                if (distinctEntries[0] > properties.edm().maxContinuationEntries()) {
                    throw bad("registry-entry-limit");
                }
            }
        });
        return new TypedFingerprintSet(counts.valuesSeen(), counts.indexed(), counts.droppedWeak(),
                fingerprints);
    }

    /**
     * Shared CSV scan skeleton for both ingestion paths: open the stream, require a header,
     * resolve the wanted columns, walk rows applying bounds and blank-row rules, normalize and
     * strength-check each selected cell, and hand accepted values to {@code onAccepted}. Only the
     * per-value fingerprinting differs between the legacy and typed paths.
     */
    private CsvScanCounts scanCsv(InputStream csv, Set<String> wantedColumns,
                                  AcceptedValueHandler onAccepted) throws IOException {
        try (var reader = new BufferedReader(new InputStreamReader(csv, StandardCharsets.UTF_8))) {
            CsvStreamReader rows = new CsvStreamReader(reader, maxRowChars, maxFieldChars);
            List<String> header = requiredHeader(rows);
            List<Integer> selected = selectedColumns(header, wantedColumns);
            long valuesSeen = 0;
            long indexed = 0;
            long droppedWeak = 0;
            List<String> row;
            while ((row = rows.readRow()) != null) {
                validateRow(row, header.size());
                if (blankRow(row)) {
                    continue;
                }
                for (int index : selected) {
                    if (index >= row.size()) {
                        continue;
                    }
                    valuesSeen++;
                    String normalized = Fingerprinter.normalize(row.get(index));
                    if (!Fingerprinter.strongEnough(normalized)) {
                        droppedWeak++;
                        continue;
                    }
                    indexed++;
                    onAccepted.accept(header.get(index), normalized);
                }
            }
            return new CsvScanCounts(valuesSeen, indexed, droppedWeak);
        }
    }

    @FunctionalInterface
    private interface AcceptedValueHandler {
        void accept(String fieldId, String normalizedValue);
    }

    private List<String> requiredHeader(CsvStreamReader rows) throws IOException {
        List<String> header = rows.readRow();
        if (header == null || header.stream().allMatch(String::isBlank)) {
            throw bad("csv-header-required");
        }
        return normalizeHeader(header);
    }

    private static boolean blankRow(List<String> row) {
        return row.size() == 1 && row.getFirst().isBlank();
    }

    private static void validateRow(List<String> row, int headerSize) {
        if (row.size() > headerSize) {
            throw bad("malformed-csv");
        }
    }

    private List<String> normalizeHeader(List<String> header) {
        List<String> out = new ArrayList<>(header.size());
        Set<String> seen = new LinkedHashSet<>();
        for (String value : header) {
            String name = value == null ? "" : value.trim();
            if (name.isBlank() || !seen.add(name)) {
                throw bad("invalid-csv-header");
            }
            out.add(name);
        }
        return out;
    }

    private List<Integer> selectedColumns(List<String> header, Set<String> wanted) {
        if (wanted.isEmpty()) {
            List<Integer> all = new ArrayList<>(header.size());
            for (int i = 0; i < header.size(); i++) {
                all.add(i);
            }
            return all;
        }
        List<Integer> selected = new ArrayList<>(wanted.size());
        for (String column : wanted) {
            int index = header.indexOf(column);
            if (index < 0) {
                throw bad("unknown-csv-column");
            }
            selected.add(index);
        }
        return selected;
    }

    private Map<String, Object> typedJson(TypedRegistry registry) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schemaVersion", TypedRegistry.SCHEMA_VERSION);
        root.put("registry", registry.id());
        root.put("version", registry.version());
        root.put("salt", Base64.getEncoder().encodeToString(registry.salt()));
        root.put("blockThreshold", registry.blockThreshold());
        root.put("recipe", Map.of(
                "id", registry.recipe().id(),
                "version", registry.recipe().version()));
        List<Map<String, Object>> fields = new ArrayList<>();
        registry.fields().values().stream().sorted(Comparator.comparing(TypedRegistry.Field::id))
                .forEach(field -> {
                    Map<String, Object> value = new LinkedHashMap<>();
                    value.put("id", field.id());
                    value.put("kind", field.kind().name());
                    value.put("fingerprints", field.fingerprints().stream()
                            .sorted().map(FullFingerprint::toHex).toList());
                    fields.add(value);
                });
        root.put("fields", fields);
        return root;
    }

    private void writeVersion(Path dir, String registry, Map<String, Object> json) throws IOException {
        Path current = currentPath(dir, registry);
        Path previous = previousPath(dir, registry);
        Path next = Files.createTempFile(dir, registry + ".", ".tmp");
        Path previousNext = null;
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(next.toFile(), json);
            if (Files.exists(current) && properties.edm().keepPrevious()) {
                previousNext = Files.createTempFile(dir, registry + ".previous.", ".tmp");
                Files.copy(current, previousNext, StandardCopyOption.REPLACE_EXISTING);
                Files.move(previousNext, previous, StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
                previousNext = null;
            }
            Files.move(next, current, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            if (!properties.edm().keepPrevious()) {
                Files.deleteIfExists(previous);
            }
        } finally {
            Files.deleteIfExists(next);
            if (previousNext != null) {
                Files.deleteIfExists(previousNext);
            }
        }
    }

    private Optional<byte[]> existingSalt(Path dir, String registry) {
        for (Path file : List.of(currentPath(dir, registry), previousPath(dir, registry))) {
            if (!Files.isRegularFile(file)) {
                continue;
            }
            try {
                JsonNode root = mapper.readTree(Files.readString(file));
                if (registry.equals(root.path("registry").asText(""))) {
                    byte[] salt = Base64.getDecoder().decode(root.path("salt").asText(""));
                    if (salt.length == SALT_BYTES) {
                        return Optional.of(salt);
                    }
                }
            } catch (Exception ignored) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    private Optional<FileView> readFileView(Path file) {
        try {
            JsonNode root = mapper.readTree(Files.readString(file));
            String registry = root.path("registry").asText("");
            String salt = root.path("salt").asText("");
            if (registry.isBlank() || salt.isBlank()) {
                return Optional.empty();
            }
            if (root.path("schemaVersion").asInt(0) == TypedRegistry.SCHEMA_VERSION) {
                long count = 0;
                for (JsonNode field : root.path("fields")) {
                    count += field.path("fingerprints").size();
                }
                return Optional.of(new FileView(registry, root.path("version").asText(""), count));
            }
            List<String> fingerprints = new ArrayList<>();
            root.path("fingerprints").forEach(node -> fingerprints.add(node.asText()));
            return Optional.of(new FileView(registry, versionDigest(fingerprints), fingerprints.size()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private Path registryDir() {
        return store.registryDir().orElseThrow(() ->
                new RegistryIngestionException(DISABLED, "edm-registry-dir-unset"));
    }

    private byte[] freshSalt() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    private static String validateName(String name) {
        if (name == null || !REGISTRY_NAME.matcher(name).matches()) {
            throw bad("invalid-registry-name");
        }
        return name;
    }

    private static List<String> sortedHex(Set<Long> fingerprints) {
        TreeSet<String> sorted = new TreeSet<>();
        for (long fingerprint : fingerprints) {
            sorted.add("%016x".formatted(fingerprint));
        }
        return List.copyOf(sorted);
    }

    static String versionDigest(List<String> sortedFingerprintHex) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            sortedFingerprintHex.stream().sorted().forEach(hex -> {
                digest.update(hex.getBytes(StandardCharsets.US_ASCII));
                digest.update((byte) '\n');
            });
            byte[] out = digest.digest();
            StringBuilder value = new StringBuilder(out.length * 2);
            for (byte b : out) {
                value.append("%02x".formatted(b));
            }
            return value.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static Path currentPath(Path dir, String registry) {
        return dir.resolve(registry + ".json");
    }

    private static Path previousPath(Path dir, String registry) {
        return dir.resolve(registry + ".previous.json");
    }

    private static boolean isCurrentFile(Path file, String registry) {
        return file.getFileName().toString().equals(registry + ".json");
    }

    private static RegistryIngestionException bad(String code) {
        return new RegistryIngestionException(BAD_REQUEST, code);
    }

    private record CsvScanCounts(long valuesSeen, long indexed, long droppedWeak) {
    }

    private record CsvFingerprintSet(long valuesSeen, long indexed, long droppedWeak,
                                     Set<Long> fingerprints) {
    }

    private record TypedFingerprintSet(long valuesSeen, long indexed, long droppedWeak,
                                       Map<String, Set<FullFingerprint>> fingerprints) {
    }

    private record FileView(String registry, String version, long distinctFingerprints) {
    }
}
