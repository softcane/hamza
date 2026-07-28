package ai.hamza.config;

import ai.hamza.continuation.ByteCount;
import ai.hamza.continuation.ManagedMetadataVerifier;
import ai.hamza.continuation.QuarantineBudget;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.extproc.ManagedContinuationRuntime;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.SecretDetector;
import ai.hamza.masking.MaskContinuationService;
import ai.hamza.masking.MaskDetectionService;
import ai.hamza.presidio.PresidioDetector;
import ai.hamza.masking.MaskPlanner;
import ai.hamza.masking.MaskScopeStore;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** Spring wiring only; Mask-and-Continue domain behavior stays plain Java. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "hamza.continuation", name = "enabled", havingValue = "true")
public class SafeContinuationConfiguration {

    @Bean
    Clock continuationClock() {
        return Clock.systemUTC();
    }

    @Bean
    QuarantineBudget quarantineBudget(HamzaProperties properties) {
        HamzaProperties.Quarantine quarantine = properties.continuation().quarantine();
        return new QuarantineBudget(
                new ByteCount(quarantine.maxBodyBytes()),
                new ByteCount(quarantine.maxTotalMemoryBytes()),
                quarantine.maxConcurrentTurns());
    }

    @Bean
    ManagedMetadataVerifier managedMetadataVerifier(HamzaProperties properties,
                                                    Clock continuationClock) {
        return ManagedMetadataVerifierFactory.create(properties, continuationClock);
    }

    @Bean
    MaskScopeStore maskScopeStore() {
        return new MaskScopeStore();
    }

    @Bean
    MaskPlanner maskPlanner(MaskScopeStore scopes, HamzaProperties properties) {
        return new MaskPlanner(scopes, properties.continuation().mask().maxSegments());
    }

    @Bean
    MaskDetectionService maskDetectionService(SecretDetector secrets, EdmMatcher edm,
                                              PolicyEngine policy,
                                              ObjectProvider<PresidioDetector> presidio,
                                              HamzaProperties properties) {
        HamzaProperties.Mask mask = properties.continuation().mask();
        return new MaskDetectionService(secrets, edm, policy, presidio.getIfAvailable(),
                mask.maxBodyBytes(), mask.maxSegments());
    }

    @Bean
    MaskContinuationService maskContinuationService(
            MaskDetectionService detection, MaskPlanner planner, MaskScopeStore scopes,
            HamzaProperties properties) {
        return new MaskContinuationService(detection, planner, scopes,
                properties.continuation().mask().maxBodyBytes());
    }

    @Bean
    ManagedContinuationRuntime managedContinuationRuntime(
            HamzaProperties properties,
            ManagedMetadataVerifier metadataVerifier,
            QuarantineBudget quarantineBudget,
            MaskContinuationService maskContinuation) {
        return new ManagedContinuationRuntime(
                new ByteCount(properties.continuation().quarantine().maxBodyBytes()),
                metadataVerifier,
                quarantineBudget,
                maskContinuation);
    }

}
