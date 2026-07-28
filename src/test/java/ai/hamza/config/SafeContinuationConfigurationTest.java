package ai.hamza.config;

import ai.hamza.continuation.ManagedMetadataVerifier;
import ai.hamza.continuation.QuarantineAdmission;
import ai.hamza.continuation.QuarantineBudget;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.edm.RegistryStore;
import ai.hamza.extproc.ManagedContinuationRuntime;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.Masker;
import ai.hamza.policy.SecretDetector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.validation.ValidationAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class SafeContinuationConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ValidationAutoConfiguration.class))
            .withUserConfiguration(TestConfiguration.class);

    @Test
    void safeDefaultDoesNotCreateManagedRuntimeBeans() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(ai.hamza.masking.MaskContinuationService.class);
            assertThat(context).doesNotHaveBean(ManagedMetadataVerifier.class);
            assertThat(context).doesNotHaveBean(QuarantineBudget.class);
            assertThat(context).doesNotHaveBean(ManagedContinuationRuntime.class);
        });
    }

    @Test
    void enabledConfigurationWiresThePlainJavaModulesWithConfiguredBounds() {
        runner.withPropertyValues(enabledProperties())
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(ai.hamza.masking.MaskContinuationService.class);
                    assertThat(context).hasSingleBean(ai.hamza.masking.MaskDetectionService.class);
                    assertThat(context).hasSingleBean(ManagedMetadataVerifier.class);
                    assertThat(context).hasSingleBean(QuarantineBudget.class);
                    assertThat(context).hasSingleBean(ManagedContinuationRuntime.class);

                    QuarantineBudget budget = context.getBean(QuarantineBudget.class);
                    assertThat(budget.tryReserve(new ai.hamza.continuation.ByteCount(1025)))
                            .isInstanceOf(QuarantineAdmission.Denied.class);

                    // The mask bounds are settings, not constants: what the operator
                    // configures must be what the Gate enforces.
                    assertThat(context.getBean(ai.hamza.masking.MaskContinuationService.class)
                            .maxBodyBytes()).isEqualTo(512);
                    assertThat(context.getBean(ai.hamza.masking.MaskPlanner.class)
                            .maxSegments()).isEqualTo(32);
                });
    }

    @Test
    void theDefaultMaskBoundsAdmitARealAgentTurn() {
        // An Agent harness appends its whole history to every request, so a managed
        // body grows with the session. The old 65,536-byte / 64-segment constants
        // Blocked every real Turn; the defaults must leave real headroom.
        HamzaProperties.Mask defaults = new HamzaProperties(null, null, null, null, null)
                .continuation().mask();
        assertThat(defaults.maxBodyBytes()).isGreaterThanOrEqualTo(1_048_576);
        assertThat(defaults.maxSegments()).isGreaterThanOrEqualTo(1_024);
    }

    @Test
    void aMaskBoundAboveTheQuarantineAdmissionBoundFailsStartup() {
        // Unreachable config: quarantine rejects the body before masking ever sees it.
        runner.withPropertyValues(enabledProperties())
                .withPropertyValues("hamza.continuation.mask.max-body-bytes=2048")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalArgumentException.class)
                            .rootCause()
                            .hasMessage("invalid-continuation-mask-admission");
                });
    }

    @Test
    void invalidSafetySettingsFailApplicationStartup() {
        runner.withPropertyValues(enabledProperties())
                .withPropertyValues(
                        "hamza.continuation.quarantine.max-body-bytes=1024",
                        "hamza.continuation.quarantine.max-total-memory-bytes=512")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalArgumentException.class)
                            .rootCause()
                            .hasMessage("invalid-continuation-quarantine");
                });
    }

    @Test
    void enabledWithoutManagedKeyOrProfileFailsApplicationStartup() {
        runner.withPropertyValues("hamza.continuation.enabled=true")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalArgumentException.class)
                            .rootCause()
                            .hasMessage("invalid-continuation-managed-admission");
                });
    }

    @Test
    void configuredCandidateBudgetControlsTheSpringMatcher(@TempDir Path registryDir)
            throws Exception {
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

        runner.withPropertyValues(enabledProperties())
                .withPropertyValues(
                        "hamza.edm.registry-dir=" + registryDir,
                        "hamza.continuation.candidate-budget=1")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(EdmMatcher.class)
                            .scanCounts("one@example.test two@example.test").complete()).isFalse();
                });
    }

    private static String[] enabledProperties() {
        String fakeKey = Base64.getEncoder().encodeToString(
                "fake-managed-metadata-key-32bytes!".getBytes(StandardCharsets.UTF_8));
        return new String[]{
                "hamza.continuation.enabled=true",
                "hamza.continuation.quarantine.max-body-bytes=1024",
                "hamza.continuation.quarantine.max-total-memory-bytes=4096",
                "hamza.continuation.quarantine.max-concurrent-turns=2",
                // The mask bound may never exceed what quarantine admits, or it would
                // be unreachable config. Both are settings; neither is a constant.
                "hamza.continuation.mask.max-body-bytes=512",
                "hamza.continuation.mask.max-segments=32",
                "hamza.continuation.managed.signing-key-base64=" + fakeKey,
                "hamza.continuation.managed.approved-profiles[0].id=codex-safe",
                "hamza.continuation.managed.approved-profiles[0].version=1",
                "hamza.continuation.managed.approved-profiles[0].agent=codex",
                "hamza.continuation.managed.approved-profiles[0].provider=openai",
                "hamza.continuation.managed.approved-profiles[0].model=gpt-5-codex",
                "hamza.continuation.managed.approved-profiles[0].adapter-wire-version=responses-v1",
                "hamza.continuation.managed.approved-profiles[0].recipe-id=synthetic-email",
                "hamza.continuation.managed.approved-profiles[0].recipe-version=1",
                "hamza.continuation.managed.approved-profiles[0].shape=ONE_WAY"
        };
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(HamzaProperties.class)
    @Import(SafeContinuationConfiguration.class)
    static class TestConfiguration {

        @Bean
        RegistryStore registryStore(HamzaProperties properties) {
            return new RegistryStore(properties);
        }

        @Bean
        EdmMatcher edmMatcher(RegistryStore registryStore, HamzaProperties properties) {
            return new EdmMatcher(registryStore, properties);
        }

        @Bean
        SecretDetector secretDetector() {
            return new SecretDetector();
        }

        @Bean
        Masker masker() {
            return new Masker();
        }

        @Bean
        PolicyEngine policyEngine(SecretDetector detector, Masker masker,
                                  HamzaProperties properties, EdmMatcher matcher) {
            return new PolicyEngine(detector, masker, properties, matcher);
        }
    }
}
