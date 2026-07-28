package ai.hamza.health;

import ai.hamza.config.HamzaProperties;
import ai.hamza.continuation.ByteCount;
import ai.hamza.continuation.QuarantineBudget;
import ai.hamza.continuation.QuarantineAdmission;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.edm.RegistryStore;
import ai.hamza.masking.MaskContinuationService;
import ai.hamza.masking.MaskDetectionService;
import ai.hamza.masking.MaskPlanner;
import ai.hamza.masking.MaskScopeStore;
import ai.hamza.policy.Action;
import ai.hamza.policy.Masker;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.SecretDetector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.mock.env.MockEnvironment;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ContinuationReadinessHealthIndicatorTest {

    @Test
    void disabledFeatureIsReadyWithoutManagedRuntimeState() {
        HamzaProperties properties = new HamzaProperties(null, null, null, null, null);
        ContinuationReadinessHealthIndicator indicator = new ContinuationReadinessHealthIndicator(
                properties, new RegistryStore(properties), Optional.empty(), Optional.empty());

        assertThat(indicator.health().getStatus().getCode()).isEqualTo("UP");
        assertThat(indicator.health().getDetails()).isEqualTo(Map.of("reason", "disabled"));
    }

    @Test
    void enabledFeatureIsNotReadyWithoutATypedRegistry() {
        HamzaProperties properties = enabledProperties(null);
        RegistryStore registries = new RegistryStore(properties);
        ContinuationReadinessHealthIndicator indicator = new ContinuationReadinessHealthIndicator(
                properties, registries, Optional.of(maskContinuation()),
                Optional.of(new QuarantineBudget(new ByteCount(1024), new ByteCount(4096), 2)));

        assertThat(indicator.health().getStatus().getCode()).isEqualTo("DOWN");
        assertThat(indicator.health().getDetails())
                .isEqualTo(Map.of("reason", "typed-registry-unavailable"));
    }

    @Test
    void allLocalPrerequisitesProduceContentFreeReadyStatus(@TempDir Path registryDir)
            throws Exception {
        writeTypedRegistry(registryDir);
        HamzaProperties properties = enabledProperties(registryDir);
        RegistryStore registries = new RegistryStore(properties);
        ContinuationReadinessHealthIndicator indicator = new ContinuationReadinessHealthIndicator(
                properties, registries, Optional.of(maskContinuation()),
                Optional.of(new QuarantineBudget(new ByteCount(1024), new ByteCount(4096), 2)));

        assertThat(indicator.health().getStatus().getCode()).isEqualTo("UP");
        assertThat(indicator.health().getDetails())
                .isEqualTo(Map.of("reason", "ready"));
        assertThat(indicator.health().toString())
                .doesNotContain("customers", "email", "synthetic-email", "11111111");
    }

    @Test
    void absentMaskServiceFailsReadinessWithOnlyABoundedReason(@TempDir Path registryDir)
            throws Exception {
        writeTypedRegistry(registryDir);
        HamzaProperties properties = enabledProperties(registryDir);
        ContinuationReadinessHealthIndicator indicator = new ContinuationReadinessHealthIndicator(
                properties, new RegistryStore(properties), Optional.empty(),
                Optional.of(new QuarantineBudget(new ByteCount(1024), new ByteCount(4096), 2)));

        assertThat(indicator.health().getStatus().getCode()).isEqualTo("DOWN");
        assertThat(indicator.health().getDetails())
                .isEqualTo(Map.of("reason", "mask-service-unavailable"));
    }

    @Test
    void exhaustedAdmissionFailsReadinessWithOnlyABoundedReason(@TempDir Path registryDir)
            throws Exception {
        writeTypedRegistry(registryDir);
        HamzaProperties properties = enabledProperties(registryDir);
        QuarantineBudget budget = new QuarantineBudget(
                new ByteCount(1024), new ByteCount(1024), 1);
        QuarantineAdmission admission = budget.tryReserve(new ByteCount(1024));
        assertThat(admission).isInstanceOf(QuarantineAdmission.Reserved.class);
        try (var reservation = ((QuarantineAdmission.Reserved) admission).reservation()) {
            assertThat(reservation).isNotNull();
            ContinuationReadinessHealthIndicator indicator = new ContinuationReadinessHealthIndicator(
                    properties, new RegistryStore(properties), Optional.of(maskContinuation()),
                    Optional.of(budget));

            assertThat(indicator.health().getStatus().getCode()).isEqualTo("DOWN");
            assertThat(indicator.health().getDetails())
                    .isEqualTo(Map.of("reason", "admission-capacity-unavailable"));
        }
    }

    private static void writeTypedRegistry(Path registryDir) throws Exception {
        Files.writeString(registryDir.resolve("typed.json"), """
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
                """);
    }

    private static HamzaProperties enabledProperties(Path registryDir) {
        String fakeKey = Base64.getEncoder().encodeToString(
                "fake-managed-metadata-key-32bytes!".getBytes(StandardCharsets.UTF_8));
        MockEnvironment env = new MockEnvironment()
                .withProperty("hamza.continuation.enabled", "true")
                .withProperty("hamza.continuation.managed.signing-key-base64", fakeKey)
                .withProperty("hamza.continuation.managed.approved-profiles[0].id", "codex-safe")
                .withProperty("hamza.continuation.managed.approved-profiles[0].version", "1")
                .withProperty("hamza.continuation.managed.approved-profiles[0].agent", "codex")
                .withProperty("hamza.continuation.managed.approved-profiles[0].provider", "openai")
                .withProperty("hamza.continuation.managed.approved-profiles[0].model", "gpt-5-codex")
                .withProperty("hamza.continuation.managed.approved-profiles[0].adapter-wire-version", "responses-v1")
                .withProperty("hamza.continuation.managed.approved-profiles[0].recipe-id", "synthetic-email")
                .withProperty("hamza.continuation.managed.approved-profiles[0].recipe-version", "1")
                .withProperty("hamza.continuation.managed.approved-profiles[0].shape", "ONE_WAY");
        if (registryDir != null) {
            env.withProperty("hamza.edm.registry-dir", registryDir.toString());
        }
        return Binder.get(env).bind("hamza", Bindable.of(HamzaProperties.class)).get();
    }

    private static MaskContinuationService maskContinuation() {
        MaskScopeStore scopes = new MaskScopeStore();
        SecretDetector detector = new SecretDetector();
        EdmMatcher matcher = new EdmMatcher(List.of(), List.of(), 1_000);
        PolicyEngine policy = new PolicyEngine(detector, new Masker(), Action.FLAG,
                Map.of(), matcher, 10);
        return new MaskContinuationService(
                new MaskDetectionService(detector, matcher, policy),
                new MaskPlanner(scopes), scopes);
    }
}
