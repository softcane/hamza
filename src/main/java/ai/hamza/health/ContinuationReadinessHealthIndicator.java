package ai.hamza.health;

import ai.hamza.config.HamzaProperties;
import ai.hamza.continuation.QuarantineBudget;
import ai.hamza.edm.RegistryStore;
import ai.hamza.masking.MaskContinuationService;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.Optional;

/** Fast, content-free readiness for the opt-in managed Mask-and-Continue path. */
@Component("continuationReadiness")
public final class ContinuationReadinessHealthIndicator implements HealthIndicator {

    private final HamzaProperties properties;
    private final RegistryStore registries;
    private final Optional<MaskContinuationService> maskContinuation;
    private final Optional<QuarantineBudget> quarantineBudget;

    public ContinuationReadinessHealthIndicator(
            HamzaProperties properties,
            RegistryStore registries,
            Optional<MaskContinuationService> maskContinuation,
            Optional<QuarantineBudget> quarantineBudget) {
        this.properties = java.util.Objects.requireNonNull(properties, "properties");
        this.registries = java.util.Objects.requireNonNull(registries, "registries");
        this.maskContinuation = java.util.Objects.requireNonNull(maskContinuation,
                "maskContinuation");
        this.quarantineBudget = java.util.Objects.requireNonNull(quarantineBudget,
                "quarantineBudget");
    }

    @Override
    public Health health() {
        if (!properties.continuation().enabled()) {
            return Health.up().withDetail("reason", "disabled").build();
        }
        if (registries.typedRegistries().isEmpty()) {
            return Health.down().withDetail("reason", "typed-registry-unavailable").build();
        }
        if (maskContinuation.isEmpty()) {
            return Health.down().withDetail("reason", "mask-service-unavailable").build();
        }
        if (quarantineBudget.isEmpty() || !quarantineBudget.get().available()) {
            return Health.down().withDetail("reason", "admission-capacity-unavailable").build();
        }
        return Health.up().withDetail("reason", "ready").build();
    }
}
