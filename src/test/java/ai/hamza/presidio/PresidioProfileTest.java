package ai.hamza.presidio;

import ai.hamza.masking.PlaceholderFamily;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PresidioProfileTest {

    private static final Path APPROVED = Path.of("detector/presidio/approved-profile.json");

    @Test
    void loadsTheRecordedApprovedProfile() {
        PresidioProfile profile = PresidioProfile.load(APPROVED);

        assertThat(profile.enabledEntities()).containsExactlyInAnyOrder("CREDIT_CARD",
                "CRYPTO", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS", "MAC_ADDRESS",
                "PHONE_NUMBER", "MEDICAL_LICENSE", "URL");
        assertThat(profile.scoreThreshold()).isEqualTo(0.75);
        assertThat(profile.language()).isEqualTo("en");
        assertThat(profile.detectorVersion()).isEqualTo("presidio:broad-pii-en:v1");
        assertThat(profile.toString()).doesNotContain("@");
    }

    @Test
    void mapsEveryApprovedEntityToItsFixedRuleAndFamily() {
        PresidioProfile profile = PresidioProfile.load(APPROVED);

        assertThat(PresidioProfile.rule("EMAIL_ADDRESS")).isEqualTo("email-address");
        assertThat(PresidioProfile.rule("CREDIT_CARD")).isEqualTo("credit-card");
        assertThat(profile.family("EMAIL_ADDRESS")).isEqualTo(PlaceholderFamily.EMAIL);
        assertThat(profile.family("CREDIT_CARD")).isEqualTo(PlaceholderFamily.ACCOUNT);
        assertThat(profile.family("IBAN_CODE")).isEqualTo(PlaceholderFamily.ACCOUNT);
        assertThat(profile.family("CRYPTO")).isEqualTo(PlaceholderFamily.ACCOUNT);
        assertThat(profile.family("IP_ADDRESS")).isEqualTo(PlaceholderFamily.IP);
        assertThat(profile.family("PHONE_NUMBER")).isEqualTo(PlaceholderFamily.PHONE);
        assertThat(profile.family("MAC_ADDRESS")).isEqualTo(PlaceholderFamily.PII);
        assertThat(profile.family("MEDICAL_LICENSE")).isEqualTo(PlaceholderFamily.PII);
        assertThat(profile.family("URL")).isEqualTo(PlaceholderFamily.PII);
        assertThat(profile.family("PERSON")).isEqualTo(PlaceholderFamily.PERSON);
        assertThat(profile.family("LOCATION")).isEqualTo(PlaceholderFamily.LOCATION);
        assertThatThrownBy(() -> profile.family("PASSPORT"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesToEnableAnEntityThatTheEvaluationDisabled(@TempDir Path temp) throws Exception {
        Path path = temp.resolve("bad.json");
        Files.writeString(path, """
                {"schema":"hamza-presidio-approved-profile/v1","profile_id":"broad-pii-en",
                 "version":1,"language":"en","selected_threshold":0.75,
                 "enabled_entities":["PERSON"],
                 "disabled_entities":[{"entity":"PERSON","reasons":["precision_below_floor"]}]}
                """);

        assertThatThrownBy(() -> PresidioProfile.load(path))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PERSON");
    }

    /**
     * The profile must not be its own authority. A hand-written profile that simply
     * omits {@code disabled_entities} must still fail to enable an entity M3 rejected.
     */
    @Test
    void refusesADisabledEntityEvenWhenTheProfileDoesNotDeclareItDisabled(@TempDir Path temp)
            throws Exception {
        for (String entity : List.of("PERSON", "LOCATION", "NRP", "DATE_TIME")) {
            Path path = temp.resolve("rogue-" + entity + ".json");
            Files.writeString(path, """
                    {"schema":"hamza-presidio-approved-profile/v1","profile_id":"broad-pii-en",
                     "version":1,"language":"en","selected_threshold":0.75,
                     "enabled_entities":["EMAIL_ADDRESS","%s"],"disabled_entities":[]}
                    """.formatted(entity));

            assertThatThrownBy(() -> PresidioProfile.load(path))
                    .as("a rogue profile must not re-enable %s", entity)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(entity);
        }
    }

    @Test
    void refusesADisabledEntityBuiltDirectlyWithoutAProfileFile() {
        assertThatThrownBy(() -> new PresidioProfile("broad-pii-en", 1, "en", 0.75,
                List.of("EMAIL_ADDRESS", "PERSON")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PERSON");
    }

    @Test
    void refusesUnknownSchemaUnevaluatedEntityAndEmptyEnabledSet(@TempDir Path temp)
            throws Exception {
        Path unknownSchema = Files.writeString(temp.resolve("schema.json"),
                "{\"schema\":\"other/v9\"}");
        assertThatThrownBy(() -> PresidioProfile.load(unknownSchema))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("schema");

        Path unevaluated = Files.writeString(temp.resolve("entity.json"), """
                {"schema":"hamza-presidio-approved-profile/v1","profile_id":"broad-pii-en",
                 "version":1,"language":"en","selected_threshold":0.75,
                 "enabled_entities":["PASSPORT"],"disabled_entities":[]}
                """);
        assertThatThrownBy(() -> PresidioProfile.load(unevaluated))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unevaluated");

        Path empty = Files.writeString(temp.resolve("empty.json"), """
                {"schema":"hamza-presidio-approved-profile/v1","profile_id":"broad-pii-en",
                 "version":1,"language":"en","selected_threshold":0.75,
                 "enabled_entities":[],"disabled_entities":[]}
                """);
        assertThatThrownBy(() -> PresidioProfile.load(empty))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsAnInvalidThresholdVersionOrIdentifier() {
        assertThatThrownBy(() -> new PresidioProfile("broad-pii-en", 1, "en", 1.5,
                java.util.List.of("URL"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PresidioProfile("broad-pii-en", 0, "en", 0.75,
                java.util.List.of("URL"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PresidioProfile("bad id", 1, "en", 0.75,
                java.util.List.of("URL"))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refusesAnUnreadableProfile(@TempDir Path temp) {
        assertThatThrownBy(() -> PresidioProfile.load(temp.resolve("missing.json")))
                .isInstanceOf(java.io.UncheckedIOException.class);
    }

    @Test
    void loadsAndAppliesAPerEntityThresholdOverride(@TempDir Path temp) throws Exception {
        Path path = temp.resolve("override.json");
        Files.writeString(path, """
                {"schema":"hamza-presidio-approved-profile/v1","profile_id":"broad-pii-en",
                 "version":1,"language":"en","selected_threshold":0.75,
                 "enabled_entities":["IP_ADDRESS","EMAIL_ADDRESS"],
                 "entity_thresholds":{"IP_ADDRESS":0.6},
                 "disabled_entities":[]}
                """);

        PresidioProfile profile = PresidioProfile.load(path);

        assertThat(profile.threshold("IP_ADDRESS")).isEqualTo(0.6);
        assertThat(profile.threshold("EMAIL_ADDRESS")).isEqualTo(0.75);
        assertThat(profile.minimumThreshold()).isEqualTo(0.6);
    }

    @Test
    void anEntityWithNoOverrideFallsBackToTheSelectedThresholdUnchanged() {
        PresidioProfile profile = new PresidioProfile("broad-pii-en", 1, "en", 0.75,
                List.of("EMAIL_ADDRESS", "IP_ADDRESS"), Map.of("IP_ADDRESS", 0.6));

        assertThat(profile.threshold("EMAIL_ADDRESS")).isEqualTo(0.75);
    }

    @Test
    void minimumThresholdEqualsTheSelectedThresholdWhenNoOverrideExists() {
        PresidioProfile profile = new PresidioProfile("broad-pii-en", 1, "en", 0.75,
                List.of("URL"));

        assertThat(profile.minimumThreshold()).isEqualTo(0.75);
    }

    @Test
    void rejectsAnOutOfRangePerEntityThresholdNamingTheEntity() {
        assertThatThrownBy(() -> new PresidioProfile("broad-pii-en", 1, "en", 0.75,
                List.of("IP_ADDRESS"), Map.of("IP_ADDRESS", 1.4)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("IP_ADDRESS");
    }

    @Test
    void rejectsAPerEntityThresholdNamingAnEntityAbsentFromEnabledEntities() {
        assertThatThrownBy(() -> new PresidioProfile("broad-pii-en", 1, "en", 0.75,
                List.of("EMAIL_ADDRESS"), Map.of("IP_ADDRESS", 0.6)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("IP_ADDRESS");
    }
}
