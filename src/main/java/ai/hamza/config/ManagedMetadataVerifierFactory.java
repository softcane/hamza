package ai.hamza.config;

import ai.hamza.continuation.ManagedMetadataVerifier;

import java.time.Clock;

/** One security-sensitive construction path shared by active and simulation rollout. */
final class ManagedMetadataVerifierFactory {

    private ManagedMetadataVerifierFactory() {
    }

    static ManagedMetadataVerifier create(HamzaProperties properties, Clock clock) {
        HamzaProperties.Managed managed = properties.continuation().managed();
        byte[] signingKey = managed.decodedSigningKey()
                .orElseThrow(() -> new IllegalStateException("managed-admission-not-configured"));
        return new ManagedMetadataVerifier(
                clock,
                managed.maxAge(),
                managed.maxFutureSkew(),
                signingKey,
                managed.approvedProfiles().stream()
                        .map(HamzaProperties.ApprovedProfile::toDomain)
                        .toList());
    }
}
