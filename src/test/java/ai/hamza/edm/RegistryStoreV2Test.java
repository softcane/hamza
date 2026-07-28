package ai.hamza.edm;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RegistryStoreV2Test {

    private static final String VALID = """
            {
              "schemaVersion": 2,
              "registry": "customers",
              "version": "a4b31799c3b3b3afd88f9c5e0eda9af9cb4b1405f5a17300d5fbedb8a1fc6764",
              "salt": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
              "blockThreshold": 1,
              "recipe": {"id": "synthetic-email", "version": 1},
              "fields": [{
                "id": "email",
                "kind": "EMAIL",
                "fingerprints": ["1111111111111111111111111111111111111111111111111111111111111111"]
              }]
            }
            """;

    @Test
    void loadsStrictTypedRegistryWithoutPretendingItIsLegacy(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("customers.json"), VALID);

        RegistryStore store = new RegistryStore(dir, 10);

        assertThat(store.registries()).isEmpty();
        assertThat(store.typedRegistries()).singleElement().satisfies(registry -> {
            assertThat(registry.id()).isEqualTo("customers");
            assertThat(registry.blockThreshold()).isEqualTo(1);
            assertThat(registry.recipe()).isEqualTo(new RegistryRecipe("synthetic-email", 1));
            assertThat(registry.fields().get("email").kind()).isEqualTo(ReplacementKind.EMAIL);
        });
    }

    @Test
    void rejectsWholeV2FileForUnknownShapeOrCanonicalVersionMismatch(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("unknown.json"), VALID.replaceFirst(
                "\\{", "{\n  \"unexpected\": true,"));
        Files.writeString(dir.resolve("mismatch.json"), VALID.replace(
                "a4b31799c3b3b3afd88f9c5e0eda9af9cb4b1405f5a17300d5fbedb8a1fc6764",
                "00".repeat(32)));

        RegistryStore store = new RegistryStore(dir, 10);

        assertThat(store.typedRegistries()).isEmpty();
        assertThat(store.registries()).isEmpty();
    }

    @Test
    void rejectsTypedRegistryAboveConfiguredEntryBoundWithoutTruncation(@TempDir Path dir) throws Exception {
        byte[] salt = "01234567890123456789012345678901".getBytes();
        TypedRegistry registry = TypedRegistry.create("customers", salt, 1,
                new RegistryRecipe("synthetic-email", 1),
                Map.of("email", new TypedRegistry.Field("email", ReplacementKind.EMAIL,
                        Set.of(FullFingerprint.parseHex("11".repeat(32)),
                                FullFingerprint.parseHex("22".repeat(32))))));
        Files.writeString(dir.resolve("customers.json"), json(registry));

        RegistryStore store = new RegistryStore(dir, 1);

        assertThat(store.typedRegistries()).isEmpty();
    }

    @Test
    void legacyRegistryRemainsReadableBesideTypedRegistry(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("customers.json"), VALID);
        Files.writeString(dir.resolve("legacy.json"), """
                {"registry":"legacy","salt":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",\
                "fingerprints":["0123456789abcdef"]}
                """);

        RegistryStore store = new RegistryStore(dir, 10);

        assertThat(store.typedRegistries()).extracting(TypedRegistry::id).containsExactly("customers");
        assertThat(store.registries()).extracting(FingerprintRegistry::name).containsExactly("legacy");
    }

    private static String json(TypedRegistry registry) throws Exception {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("schemaVersion", 2);
        root.put("registry", registry.id());
        root.put("version", registry.version());
        root.put("salt", Base64.getEncoder().encodeToString(registry.salt()));
        root.put("blockThreshold", registry.blockThreshold());
        root.put("recipe", Map.of("id", registry.recipe().id(), "version", registry.recipe().version()));
        root.put("fields", registry.fields().values().stream().map(field -> Map.of(
                "id", field.id(),
                "kind", field.kind().name(),
                "fingerprints", field.fingerprints().stream().map(FullFingerprint::toHex).sorted().toList()
        )).toList());
        return new ObjectMapper().writeValueAsString(root);
    }
}
