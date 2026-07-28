package ai.hamza.edm;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RegistryIngestCommandTest {

    @Test
    void parsesLegacyAndCompleteTypedTransportGrammar() {
        RegistryIngestCommand legacy = RegistryIngestCommand.fromQuery(
                "customers", Map.of("columns", List.of("email,name")));
        RegistryIngestCommand typed = RegistryIngestCommand.fromQuery("customers", Map.of(
                "columns", List.of("email"),
                "replacementKinds", List.of("email:EMAIL"),
                "recipe", List.of("synthetic-email:1"),
                "blockThreshold", List.of("1")));

        assertThat(legacy.typed()).isFalse();
        assertThat(legacy.columns()).containsExactly("email", "name");
        assertThat(typed.typed()).isTrue();
        assertThat(typed.replacementKinds()).containsEntry("email", ReplacementKind.EMAIL);
        assertThat(typed.recipe()).isEqualTo(new RegistryRecipe("synthetic-email", 1));
        assertThat(typed.blockThreshold()).isEqualTo(1);
    }

    @Test
    void partialUnknownDuplicateAndIncompatibleMetadataShareOneFixedError() {
        List<Map<String, List<String>>> invalid = List.of(
                Map.of("columns", List.of("email"), "recipe", List.of("synthetic-email:1")),
                Map.of("columns", List.of("email"), "unknown", List.of("x")),
                Map.of("columns", List.of("email", "name")),
                Map.of("columns", List.of("email"),
                        "replacementKinds", List.of("email:PHONE"),
                        "recipe", List.of("synthetic-email:1"),
                        "blockThreshold", List.of("1")),
                Map.of("columns", List.of("email,email"),
                        "replacementKinds", List.of("email:EMAIL"),
                        "recipe", List.of("synthetic-email:1"),
                        "blockThreshold", List.of("1")),
                Map.of("columns", List.of("email"),
                        "replacementKinds", List.of("email:EMAIL"),
                        "recipe", List.of("synthetic-email:1"),
                        "blockThreshold", List.of("2")));

        invalid.forEach(query -> assertThatThrownBy(() ->
                RegistryIngestCommand.fromQuery("customers", query))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo(RegistryIngestCommand.INVALID_REQUEST));
    }

    @Test
    void typedTransportMetadataHasAFixedFieldCountBound() {
        List<String> columns = IntStream.range(0, 65).mapToObj(index -> "field" + index).toList();
        String selected = String.join(",", columns);
        String kinds = columns.stream().map(column -> column + ":EMAIL")
                .collect(java.util.stream.Collectors.joining(","));

        assertThatThrownBy(() -> RegistryIngestCommand.fromQuery("customers", Map.of(
                "columns", List.of(selected),
                "replacementKinds", List.of(kinds),
                "recipe", List.of("synthetic-email:1"),
                "blockThreshold", List.of("1"))))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo(RegistryIngestCommand.INVALID_REQUEST);
    }

    @Test
    void everyTransportMetadataValueHasAFixedCharacterBound() {
        assertThatThrownBy(() -> RegistryIngestCommand.fromQuery(
                "customers", Map.of("columns", List.of("a".repeat(4097)))))
                .isInstanceOf(RegistryIngestionException.class)
                .extracting("code")
                .isEqualTo(RegistryIngestCommand.INVALID_REQUEST);
    }
}
