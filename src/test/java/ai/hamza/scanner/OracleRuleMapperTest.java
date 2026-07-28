package ai.hamza.scanner;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Rule-id normalisation: active Rulepack ids vs {@code oracle:<id>} namespacing (Q15). */
class OracleRuleMapperTest {

    private final OracleRuleMapper mapper = new OracleRuleMapper();

    @Test
    void mapsOracleRulesToStableHamzaIdsWhenNativeEquivalentExists() {
        assertThat(mapper.toStableId("aws-access-token")).isEqualTo("aws-access-token");
        assertThat(mapper.toStableId("aws-access-key-id")).isEqualTo("aws-access-token");
        assertThat(mapper.toStableId("gcp-api-key")).isEqualTo("gcp-api-key");
        assertThat(mapper.toStableId("google-api-key")).isEqualTo("gcp-api-key");
        assertThat(mapper.toStableId("github-oauth")).isEqualTo("github-oauth");
        assertThat(mapper.toStableId("github-oauth-token")).isEqualTo("github-oauth");
        assertThat(mapper.toStableId("stripe-access-token")).isEqualTo("stripe-access-token");
        assertThat(mapper.toStableId("npm-access-token")).isEqualTo("npm-access-token");
    }

    @Test
    void namespacesUnknownOracleRules() {
        // generic-api-key and azure-storage-account-key are not activated in-process, so a
        // finding for them from the offline oracle is namespaced (not deduped as native).
        assertThat(mapper.toStableId("generic-api-key")).isEqualTo("oracle:generic-api-key");
        assertThat(mapper.toStableId("azure-storage-account-key")).isEqualTo("oracle:azure-storage-account-key");
    }

    @Test
    void confidenceIsHighForNativeEquivalentsAndMediumForNamespaced() {
        assertThat(mapper.confidenceFor("aws-access-token")).isEqualTo(Confidence.HIGH);
        assertThat(mapper.confidenceFor("openai-api-key")).isEqualTo(Confidence.HIGH);
        assertThat(mapper.hasNativeEquivalent("stripe-access-token")).isTrue();
        // Phase 3 activated these natively; the mapper now resolves them to their own ids.
        assertThat(mapper.toStableId("private-key")).isEqualTo("private-key");
        assertThat(mapper.toStableId("jwt")).isEqualTo("jwt");
        assertThat(mapper.confidenceFor("private-key")).isEqualTo(Confidence.HIGH);
        assertThat(mapper.confidenceFor("generic-api-key")).isEqualTo(Confidence.MEDIUM);
        assertThat(mapper.hasNativeEquivalent("generic-api-key")).isFalse();
    }

    @Test
    void rejectsBlankRuleId() {
        assertThatThrownBy(() -> mapper.toStableId("  ")).isInstanceOf(IllegalArgumentException.class);
    }
}
