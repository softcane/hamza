package ai.hamza.continuation;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ManagedMetadataVerifierTest {

    private static final byte[] KEY = "managed-metadata-test-key-32-bytes".getBytes(StandardCharsets.UTF_8);
    private static final Instant NOW = Instant.parse("2026-07-11T12:00:00Z");
    private static final WorkflowProfile PROFILE = new WorkflowProfile(
            "email-one-way", 1, "codex", "openai", "gpt-5-codex",
            "openai-responses/v1", "synthetic-email", 1, WorkflowShape.ONE_WAY);

    private final ManagedMetadataVerifier verifier = new ManagedMetadataVerifier(
            Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(5), Duration.ofSeconds(30),
            KEY, List.of(PROFILE));

    @Test
    void aCompleteSignedSelectionResolvesOnlyTheServerSideProfile() {
        Map<String, List<String>> headers = signedHeaders(PROFILE, NOW.minusSeconds(10));

        ManagedMetadataDecision decision = verifier.verify(headers);

        assertThat(decision).isInstanceOfSatisfying(ManagedMetadataDecision.Verified.class, verified -> {
            assertThat(verified.recoveryId().value()).isEqualTo("recovery_0123456789abcdef");
            assertThat(verified.profile()).isEqualTo(PROFILE);
            assertThat(verified.issuedAt()).isEqualTo(NOW.minusSeconds(10));
        });
        assertThat(ManagedMetadataVerifier.internalHeaderNames())
                .containsExactlyInAnyOrderElementsOf(headers.keySet());
    }

    @Test
    void noInternalMetadataIsAbsentButAnyPartialSelectionIsInvalid() {
        assertThat(verifier.verify(Map.of())).isEqualTo(ManagedMetadataDecision.Absent.INSTANCE);

        assertInvalid(Map.of(ManagedMetadataVerifier.RECOVERY_ID, List.of("recovery_0123456789abcdef")),
                ManagedMetadataReason.INCOMPLETE);
    }

    @Test
    void duplicatesUnknownInternalHeadersAndForgedSignaturesAreRejected() {
        Map<String, List<String>> duplicate = signedHeaders(PROFILE, NOW);
        duplicate.put(ManagedMetadataVerifier.AGENT, List.of("codex", "codex"));
        assertInvalid(duplicate, ManagedMetadataReason.DUPLICATE);

        Map<String, List<String>> unknown = signedHeaders(PROFILE, NOW);
        unknown.put("x-hamza-user-template", List.of("anything"));
        assertInvalid(unknown, ManagedMetadataReason.UNKNOWN_HEADER);

        Map<String, List<String>> forged = signedHeaders(PROFILE, NOW);
        forged.put(ManagedMetadataVerifier.MODEL, List.of("gpt-unknown"));
        assertInvalid(forged, ManagedMetadataReason.BAD_SIGNATURE);
    }

    @Test
    void staleFutureAndUncertifiedTuplesAreRejectedWithBoundedReasons() {
        assertInvalid(signedHeaders(PROFILE, NOW.minus(Duration.ofMinutes(6))),
                ManagedMetadataReason.EXPIRED);
        assertInvalid(signedHeaders(PROFILE, NOW.plusSeconds(31)),
                ManagedMetadataReason.FUTURE);

        WorkflowProfile unknown = new WorkflowProfile(
                "email-one-way", 2, "codex", "openai", "gpt-5-codex",
                "openai-responses/v1", "synthetic-email", 1, WorkflowShape.ONE_WAY);
        assertInvalid(signedHeaders(unknown, NOW), ManagedMetadataReason.PROFILE_NOT_APPROVED);
    }

    @Test
    void recoveryAndProfileValueObjectsDoNotRevealOpaqueIdsFromToString() {
        RecoveryId recoveryId = RecoveryId.parse("recovery_0123456789abcdef");

        assertThat(recoveryId.toString()).isEqualTo("<recovery-id>");
        assertThat(PROFILE.toString()).doesNotContain("recovery_0123456789abcdef");
    }

    private void assertInvalid(Map<String, List<String>> headers, ManagedMetadataReason reason) {
        assertThat(verifier.verify(headers))
                .isEqualTo(new ManagedMetadataDecision.Invalid(reason));
    }

    private static Map<String, List<String>> signedHeaders(WorkflowProfile profile, Instant issuedAt) {
        Map<String, String> scalar = new LinkedHashMap<>();
        scalar.put(ManagedMetadataVerifier.RECOVERY_ID, "recovery_0123456789abcdef");
        scalar.put(ManagedMetadataVerifier.PROFILE_ID, profile.id());
        scalar.put(ManagedMetadataVerifier.PROFILE_VERSION, Integer.toString(profile.version()));
        scalar.put(ManagedMetadataVerifier.AGENT, profile.agent());
        scalar.put(ManagedMetadataVerifier.PROVIDER, profile.provider());
        scalar.put(ManagedMetadataVerifier.MODEL, profile.model());
        scalar.put(ManagedMetadataVerifier.ADAPTER_WIRE_VERSION, profile.adapterWireVersion());
        scalar.put(ManagedMetadataVerifier.ISSUED_AT, Long.toString(issuedAt.getEpochSecond()));
        scalar.put(ManagedMetadataVerifier.SIGNATURE,
                ManagedMetadataSignature.sign(scalar, KEY));
        Map<String, List<String>> headers = new LinkedHashMap<>();
        scalar.forEach((name, value) -> headers.put(name, List.of(value)));
        return headers;
    }
}
