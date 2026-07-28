package ai.hamza.continuation;

import java.time.Instant;
import java.util.Objects;

/** Result of authenticating internal managed-Agent metadata. */
public sealed interface ManagedMetadataDecision
        permits ManagedMetadataDecision.Verified, ManagedMetadataDecision.Invalid,
        ManagedMetadataDecision.Absent {

    record Verified(RecoveryId recoveryId, WorkflowProfile profile, Instant issuedAt)
            implements ManagedMetadataDecision {
        public Verified {
            recoveryId = Objects.requireNonNull(recoveryId, "recoveryId");
            profile = Objects.requireNonNull(profile, "profile");
            issuedAt = Objects.requireNonNull(issuedAt, "issuedAt");
        }
    }

    record Invalid(ManagedMetadataReason reason) implements ManagedMetadataDecision {
        public Invalid {
            reason = Objects.requireNonNull(reason, "reason");
        }
    }

    enum Absent implements ManagedMetadataDecision {
        INSTANCE
    }
}
