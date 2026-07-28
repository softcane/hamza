package ai.hamza.config;

import ai.hamza.continuation.WorkflowShape;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.mock.env.MockEnvironment;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HamzaPropertiesContinuationTest {

    @Test
    void safeContinuationIsOffAndBoundedByDefault() {
        HamzaProperties.Continuation continuation = new HamzaProperties(
                null, null, null, null, null).continuation();

        assertThat(continuation.enabled()).isFalse();
        assertThat(continuation.quarantine().maxBodyBytes()).isEqualTo(8L * 1024 * 1024);
        assertThat(continuation.quarantine().maxTotalMemoryBytes())
                .isGreaterThanOrEqualTo(continuation.quarantine().maxBodyBytes());
        assertThat(continuation.quarantine().maxConcurrentTurns()).isPositive();
        assertThat(continuation.candidateBudget()).isPositive();
        assertThat(continuation.managed().approvedProfiles()).isEmpty();
        assertThat(continuation.managed().decodedSigningKey()).isEmpty();
    }

    @Test
    void bindsManagedBoundsAndApprovedProfilesWithoutRenderingKeyMaterial() {
        String fakeKey = Base64.getEncoder().encodeToString(
                "fake-managed-metadata-key-32bytes!".getBytes(StandardCharsets.UTF_8));
        MockEnvironment env = new MockEnvironment()
                .withProperty("hamza.continuation.enabled", "true")
                .withProperty("hamza.continuation.quarantine.max-body-bytes", "8388608")
                .withProperty("hamza.continuation.quarantine.max-total-memory-bytes", "67108864")
                .withProperty("hamza.continuation.quarantine.max-concurrent-turns", "4")
                .withProperty("hamza.continuation.candidate-budget", "75000")
                .withProperty("hamza.continuation.mask.max-body-bytes", "2097152")
                .withProperty("hamza.continuation.mask.max-segments", "512")
                .withProperty("hamza.continuation.managed.signing-key-base64", fakeKey)
                .withProperty("hamza.continuation.managed.max-age", "5m")
                .withProperty("hamza.continuation.managed.max-future-skew", "30s")
                .withProperty("hamza.continuation.managed.approved-profiles[0].id", "codex-safe")
                .withProperty("hamza.continuation.managed.approved-profiles[0].version", "1")
                .withProperty("hamza.continuation.managed.approved-profiles[0].agent", "codex")
                .withProperty("hamza.continuation.managed.approved-profiles[0].provider", "openai")
                .withProperty("hamza.continuation.managed.approved-profiles[0].model", "gpt-5-codex")
                .withProperty("hamza.continuation.managed.approved-profiles[0].adapter-wire-version", "responses-v1")
                .withProperty("hamza.continuation.managed.approved-profiles[0].recipe-id", "synthetic-email")
                .withProperty("hamza.continuation.managed.approved-profiles[0].recipe-version", "1")
                .withProperty("hamza.continuation.managed.approved-profiles[0].shape", "ONE_WAY");

        HamzaProperties props = Binder.get(env)
                .bind("hamza", Bindable.of(HamzaProperties.class))
                .get();

        HamzaProperties.Continuation continuation = props.continuation();
        assertThat(continuation.enabled()).isTrue();
        assertThat(continuation.candidateBudget()).isEqualTo(75_000);
        assertThat(continuation.mask().maxBodyBytes()).isEqualTo(2_097_152);
        assertThat(continuation.mask().maxSegments()).isEqualTo(512);
        assertThat(continuation.managed().decodedSigningKey()).hasValueSatisfying(
                key -> assertThat(key).hasSizeGreaterThanOrEqualTo(32));
        byte[] firstRead = continuation.managed().decodedSigningKey().orElseThrow();
        firstRead[0] ^= 0x7f;
        assertThat(continuation.managed().decodedSigningKey().orElseThrow()[0])
                .isNotEqualTo(firstRead[0]);
        assertThat(continuation.managed().approvedProfiles()).singleElement()
                .satisfies(profile -> {
                    assertThat(profile.shape()).isEqualTo(WorkflowShape.ONE_WAY);
                    assertThat(profile.toDomain().provider()).isEqualTo("openai");
                });
        assertThat(props.toString()).doesNotContain(fakeKey, "fake-managed-metadata-key");
    }

    @Test
    void rejectsUnsafeCrossFieldBoundsInsteadOfCorrectingThem() {
        assertThatThrownBy(() -> new HamzaProperties.Quarantine(
                8L * 1024 * 1024, 1024, 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("invalid-continuation-quarantine");

        // A mask bound above the quarantine admission bound is unreachable config.
        assertThatThrownBy(() -> new HamzaProperties.Continuation(false,
                new HamzaProperties.Quarantine(1024, 4096, 1), 50_000, null,
                new HamzaProperties.Mask(2048, 32)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("invalid-continuation-mask-admission");
    }

    @Test
    void defaultQuarantineAdmitsEverySupportedMaskBodySize() {
        HamzaProperties.Continuation continuation = new HamzaProperties.Continuation(
                false, null, 50_000, null,
                new HamzaProperties.Mask(8 * 1024 * 1024, 1_024));

        assertThat(continuation.mask().maxBodyBytes())
                .isEqualTo(continuation.quarantine().maxBodyBytes());
    }

    @Test
    void rejectsEachInvalidResourceBound() {
        List<Runnable> invalidMaskSettings = List.of(
                () -> new HamzaProperties.Mask(0, 64),
                () -> new HamzaProperties.Mask(8 * 1024 * 1024 + 1, 64),
                () -> new HamzaProperties.Mask(65_536, 0),
                () -> new HamzaProperties.Mask(65_536, 8_193));
        invalidMaskSettings.forEach(setting -> assertThatThrownBy(setting::run)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("invalid-continuation-mask"));

        List<Runnable> invalidQuarantineSettings = List.of(
                () -> new HamzaProperties.Quarantine(0, 1024, 1),
                () -> new HamzaProperties.Quarantine(64L * 1024 * 1024 + 1,
                        128L * 1024 * 1024, 1),
                () -> new HamzaProperties.Quarantine(1024, 512, 1),
                () -> new HamzaProperties.Quarantine(1024,
                        2L * 1024 * 1024 * 1024 + 1, 1),
                () -> new HamzaProperties.Quarantine(1024, 4096, 0),
                () -> new HamzaProperties.Quarantine(1024, 4096, 257));
        invalidQuarantineSettings.forEach(setting -> assertThatThrownBy(setting::run)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("invalid-continuation-quarantine"));
    }

    @Test
    void rejectsEachInvalidRolloutAndManagedBound() {
        List<Runnable> invalidRolloutSettings = List.of(
                () -> new HamzaProperties.Continuation(false,
                        null, 0, null, null),
                () -> new HamzaProperties.Continuation(false,
                        null, 5_000_001, null, null),
                () -> new HamzaProperties.Continuation(true,
                        null, 50_000, null, null));
        invalidRolloutSettings.forEach(setting -> assertThatThrownBy(setting::run)
                .isInstanceOf(IllegalArgumentException.class));

        HamzaProperties.ApprovedProfile profile = approvedProfile();
        List<Runnable> invalidManagedSettings = List.of(
                () -> new HamzaProperties.Managed("x".repeat(1025),
                        Duration.ofMinutes(5), Duration.ofSeconds(30), List.of()),
                () -> new HamzaProperties.Managed("", null,
                        Duration.ofSeconds(30), List.of()),
                () -> new HamzaProperties.Managed("", Duration.ZERO,
                        Duration.ofSeconds(30), List.of()),
                () -> new HamzaProperties.Managed("", Duration.ofMinutes(16),
                        Duration.ofSeconds(30), List.of()),
                () -> new HamzaProperties.Managed("", Duration.ofMinutes(5),
                        null, List.of()),
                () -> new HamzaProperties.Managed("", Duration.ofMinutes(5),
                        Duration.ofSeconds(-1), List.of()),
                () -> new HamzaProperties.Managed("", Duration.ofMinutes(5),
                        Duration.ofMinutes(6), List.of()),
                () -> new HamzaProperties.Managed("", Duration.ofMinutes(5),
                        Duration.ofSeconds(30), Collections.nCopies(65, profile)),
                () -> new HamzaProperties.Managed("", Duration.ofMinutes(5),
                        Duration.ofSeconds(30), List.of(profile, profile)),
                () -> new HamzaProperties.Managed("not-base64", Duration.ofMinutes(5),
                        Duration.ofSeconds(30), List.of()),
                () -> new HamzaProperties.Managed(Base64.getEncoder().encodeToString(new byte[31]),
                        Duration.ofMinutes(5), Duration.ofSeconds(30), List.of()),
                () -> new HamzaProperties.Managed(Base64.getEncoder().encodeToString(new byte[65]),
                        Duration.ofMinutes(5), Duration.ofSeconds(30), List.of()));
        invalidManagedSettings.forEach(setting -> assertThatThrownBy(setting::run)
                .isInstanceOf(IllegalArgumentException.class));
    }

    private static HamzaProperties.ApprovedProfile approvedProfile() {
        return new HamzaProperties.ApprovedProfile(
                "codex-safe", 1, "codex", "openai", "gpt-5-codex",
                "responses-v1", "synthetic-email", 1, WorkflowShape.ONE_WAY);
    }
}
