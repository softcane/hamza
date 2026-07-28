package ai.hamza.config;

import ai.hamza.continuation.WorkflowShape;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class EffectiveConfigFingerprintTest {

    @Test
    void continuationBoundsAndCertifiedTupleChangeTheEffectiveFingerprint() {
        HamzaProperties defaults = new HamzaProperties(null, null, null, null, null);
        HamzaProperties.Continuation c = defaults.continuation();
        HamzaProperties bounded = withContinuation(defaults, new HamzaProperties.Continuation(
                false, c.quarantine(), c.candidateBudget() + 1,
                c.managed(), c.mask()));
        HamzaProperties masked = withContinuation(defaults, new HamzaProperties.Continuation(
                false, c.quarantine(), c.candidateBudget(), c.managed(),
                new HamzaProperties.Mask(c.mask().maxBodyBytes() * 2, c.mask().maxSegments())));

        var profile = new HamzaProperties.ApprovedProfile(
                "repo-safe-edit", 1, "codex", "openai", "gpt-5-codex",
                "codex-0.144", "synthetic-email", 1, WorkflowShape.ONE_WAY);
        var managed = new HamzaProperties.Managed(
                "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
                c.managed().maxAge(), c.managed().maxFutureSkew(), List.of(profile));
        HamzaProperties certified = withContinuation(defaults,
                new HamzaProperties.Continuation(true, c.quarantine(),
                        c.candidateBudget(), managed, c.mask()));

        String baseline = EffectiveConfigFingerprint.of(defaults);
        assertThat(EffectiveConfigFingerprint.of(bounded)).isNotEqualTo(baseline);
        assertThat(EffectiveConfigFingerprint.of(masked)).isNotEqualTo(baseline);
        assertThat(EffectiveConfigFingerprint.of(certified)).isNotEqualTo(baseline);
        assertThat(baseline).matches("[0-9a-f]{64}");
    }

    private static HamzaProperties withContinuation(HamzaProperties source,
                                                    HamzaProperties.Continuation continuation) {
        return new HamzaProperties(source.metrics(), source.policy(), source.edm(),
                source.coach(), continuation);
    }
}
