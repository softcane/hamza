package ai.hamza.edm;

import ai.hamza.config.HamzaProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RegistryIngestionServiceTest {

    @TempDir
    Path tmp;

    @Test
    void receiptReportsCountsWithoutRawValues() throws Exception {
        RegistryStore store = store(true);
        RegistryIngestionService service = service(store, true);

        RegistryIngestionReceipt receipt = service.ingest("customers", csv("""
                email,name
                fake101@example-corp.test,Ada
                fake102@example-corp.test,Jane Smith
                fake103@example-corp.test,Bob Lee
                """), "email,name");

        assertThat(receipt.registry()).isEqualTo("customers");
        assertThat(receipt.version()).matches("[0-9a-f]{64}");
        assertThat(receipt.valuesSeen()).isEqualTo(6);
        assertThat(receipt.indexed()).isEqualTo(5);
        assertThat(receipt.droppedWeak()).isEqualTo(1);
        assertThat(receipt.distinctFingerprints()).isEqualTo(5);
        assertThat(store.registries()).hasSize(1);
        assertThat(Files.readString(tmp.resolve("customers.json")))
                .doesNotContain("example-corp.test")
                .doesNotContain("Jane Smith");
    }

    @Test
    void rePushKeepsSaltStableAndReturnsSameVersion() {
        RegistryStore store = store(true);
        RegistryIngestionService service = service(store, true);
        String csv = emailsCsv(1, 12);

        RegistryIngestionReceipt first = service.ingest("customers", csv(csv), "email");
        RegistryIngestionReceipt second = service.ingest("customers", csv(csv), "email");

        assertThat(second.version()).isEqualTo(first.version());
        assertThat(service.listRegistries()).singleElement().satisfies(stats -> {
            assertThat(stats.registry()).isEqualTo("customers");
            assertThat(stats.versions()).hasSize(2);
            assertThat(stats.versions()).allSatisfy(v ->
                    assertThat(v.version()).isEqualTo(first.version()));
        });
    }

    @Test
    void previousVersionRemainsMatchableUnderTheSameRuleName() {
        RegistryStore store = store(true);
        RegistryIngestionService service = service(store, true);
        service.ingest("customers", csv(emailsCsv(1, 12)), "email");
        service.ingest("customers", csv(emailsCsv(13, 24)), "email");

        EdmMatcher matcher = new EdmMatcher(store);

        assertThat(store.registries()).hasSize(2);
        assertThat(matcher.match("fake001@example-corp.test fake013@example-corp.test"))
                .containsExactly(Map.entry("customers", 2));
    }

    @Test
    void deleteErasesAllVersionsAndHotReloadsMatcher() {
        RegistryStore store = store(true);
        RegistryIngestionService service = service(store, true);
        service.ingest("customers", csv(emailsCsv(1, 12)), "email");
        service.ingest("customers", csv(emailsCsv(13, 24)), "email");

        service.delete("customers");

        assertThat(store.registries()).isEmpty();
        assertThat(Files.exists(tmp.resolve("customers.json"))).isFalse();
        assertThat(Files.exists(tmp.resolve("customers.previous.json"))).isFalse();
        assertThat(new EdmMatcher(store).match("fake001@example-corp.test")).isEmpty();
    }

    @Test
    void keepPreviousCanBeDisabled() {
        RegistryStore store = store(false);
        RegistryIngestionService service = service(store, false);
        service.ingest("customers", csv(emailsCsv(1, 12)), "email");
        service.ingest("customers", csv(emailsCsv(13, 24)), "email");

        assertThat(store.registries()).hasSize(1);
        assertThat(new EdmMatcher(store).match("fake001@example-corp.test")).isEmpty();
        assertThat(new EdmMatcher(store).match("fake013@example-corp.test"))
                .containsEntry("customers", 1);
    }

    @Test
    void oversizedRowsFailBeforeMaterializingTheDataset() {
        RegistryStore store = store(true);
        RegistryIngestionService service = new RegistryIngestionService(store, props(true),
                new ObjectMapper(), new SecureRandom(), 32, 256);

        assertThatThrownBy(() -> service.ingest("customers",
                csv("email\n" + "x".repeat(64) + "\n"), "email"))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo("csv-row-too-large");
    }

    @Test
    void emptyMalformedAndUnknownColumnInputsAreRejectedContentFree() {
        RegistryIngestionService service = service(store(true), true);

        assertThatThrownBy(() -> service.ingest("customers", csv(""), "email"))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo("csv-header-required");
        assertThatThrownBy(() -> service.ingest("customers", csv("email\n\"unterminated\n"), "email"))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo("malformed-csv");
        assertThatThrownBy(() -> service.ingest("customers", csv("email\nfake001@example-corp.test\n"), "name"))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo("unknown-csv-column");
    }

    @Test
    void typedIngestionWritesFullWidthFieldMetadataAndHotLoadsIt() throws Exception {
        RegistryStore store = store(true);
        RegistryIngestionService service = service(store, true);
        RegistryIngestCommand command = RegistryIngestCommand.fromQuery("customers", Map.of(
                "columns", List.of("email"),
                "replacementKinds", List.of("email:EMAIL"),
                "recipe", List.of("synthetic-email:1"),
                "blockThreshold", List.of("1")));

        RegistryIngestionReceipt receipt = service.ingest(command, csv(emailsCsv(1, 2)));

        assertThat(receipt.distinctFingerprints()).isEqualTo(2);
        assertThat(store.registries()).isEmpty();
        assertThat(store.typedRegistries()).singleElement().satisfies(registry -> {
            assertThat(registry.version()).isEqualTo(receipt.version());
            assertThat(registry.blockThreshold()).isEqualTo(1);
            assertThat(registry.fields().get("email").fingerprints())
                    .allSatisfy(fingerprint -> assertThat(fingerprint.toHex()).hasSize(64));
        });
        String persisted = Files.readString(tmp.resolve("customers.json"));
        assertThat(persisted).contains("\"schemaVersion\" : 2", "\"kind\" : \"EMAIL\"")
                .doesNotContain("example-corp.test");
    }

    @Test
    void injectedFullFingerprintCollisionRejectsBeforeRotation() throws Exception {
        RegistryStore store = store(true);
        RegistryIngestionService service = service(store, true);
        service.ingest("customers", csv(emailsCsv(1, 1)), "email");
        byte[] before = Files.readAllBytes(tmp.resolve("customers.json"));
        FullFingerprint collision = FullFingerprint.parseHex("11".repeat(32));
        RegistryIngestionService colliding = new RegistryIngestionService(
                store, props(true), new ObjectMapper(), new SecureRandom(),
                CsvStreamReader.DEFAULT_MAX_ROW_CHARS, CsvStreamReader.DEFAULT_MAX_FIELD_CHARS,
                (salt, normalized) -> collision);
        RegistryIngestCommand command = RegistryIngestCommand.fromQuery("customers", Map.of(
                "columns", List.of("email"),
                "replacementKinds", List.of("email:EMAIL"),
                "recipe", List.of("synthetic-email:1"),
                "blockThreshold", List.of("1")));

        assertThatThrownBy(() -> colliding.ingest(command, csv(emailsCsv(2, 3))))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo("full-fingerprint-collision");
        assertThat(Files.readAllBytes(tmp.resolve("customers.json"))).isEqualTo(before);
    }

    @Test
    void unknownTypedColumnDoesNotWriteOrRotateTheCurrentRegistry() throws Exception {
        RegistryStore store = store(true);
        RegistryIngestionService service = service(store, true);
        service.ingest("customers", csv(emailsCsv(1, 1)), "email");
        byte[] before = Files.readAllBytes(tmp.resolve("customers.json"));
        RegistryIngestCommand command = RegistryIngestCommand.fromQuery("customers", Map.of(
                "columns", List.of("email"),
                "replacementKinds", List.of("email:EMAIL"),
                "recipe", List.of("synthetic-email:1"),
                "blockThreshold", List.of("1")));

        assertThatThrownBy(() -> service.ingest(command,
                csv("name\nJane Smith\n")))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo("unknown-csv-column");
        assertThat(Files.readAllBytes(tmp.resolve("customers.json"))).isEqualTo(before);
        assertThat(Files.exists(tmp.resolve("customers.previous.json"))).isFalse();
    }

    @Test
    void typedEntryBoundRejectsWithoutCreatingOrTruncatingARegistry() {
        HamzaProperties limitedProps = new HamzaProperties(null, null,
                new HamzaProperties.Edm(tmp.toString(), 10, true, "test-admin-token", 1));
        RegistryStore store = new RegistryStore(limitedProps);
        RegistryIngestionService service = new RegistryIngestionService(store, limitedProps);
        RegistryIngestCommand command = RegistryIngestCommand.fromQuery("customers", Map.of(
                "columns", List.of("email"),
                "replacementKinds", List.of("email:EMAIL"),
                "recipe", List.of("synthetic-email:1"),
                "blockThreshold", List.of("1")));

        assertThatThrownBy(() -> service.ingest(command, csv(emailsCsv(1, 2))))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo("registry-entry-limit");
        assertThat(Files.exists(tmp.resolve("customers.json"))).isFalse();
    }

    private RegistryStore store(boolean keepPrevious) {
        return new RegistryStore(props(keepPrevious));
    }

    private RegistryIngestionService service(RegistryStore store, boolean keepPrevious) {
        return new RegistryIngestionService(store, props(keepPrevious));
    }

    private HamzaProperties props(boolean keepPrevious) {
        return new HamzaProperties(null, null,
                new HamzaProperties.Edm(tmp.toString(), 10, keepPrevious, "test-admin-token"));
    }

    private static ByteArrayInputStream csv(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String emailsCsv(int from, int to) {
        StringBuilder out = new StringBuilder("email\n");
        for (int i = from; i <= to; i++) {
            out.append("fake%03d@example-corp.test%n".formatted(i));
        }
        return out.toString();
    }
}
