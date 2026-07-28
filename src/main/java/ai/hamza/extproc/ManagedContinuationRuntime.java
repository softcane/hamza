package ai.hamza.extproc;

import ai.hamza.continuation.ByteCount;
import ai.hamza.continuation.ManagedMetadataVerifier;
import ai.hamza.continuation.QuarantineBudget;
import ai.hamza.masking.MaskContinuationService;

import java.util.Objects;

/** Validated runtime dependencies for the explicit fail-closed managed route. */
public final class ManagedContinuationRuntime {

    private final boolean enabled;
    private final long maxBodyBytes;
    private final ManagedMetadataVerifier metadataVerifier;
    private final QuarantineBudget quarantineBudget;
    private final MaskContinuationService maskContinuation;

    public ManagedContinuationRuntime(ByteCount maxBodyBytes,
                                      ManagedMetadataVerifier metadataVerifier,
                                      QuarantineBudget quarantineBudget,
                                      MaskContinuationService maskContinuation) {
        if (maxBodyBytes == null || maxBodyBytes.value() == 0) {
            throw new IllegalArgumentException("managed body bound must be positive");
        }
        this.enabled = true;
        this.maxBodyBytes = maxBodyBytes.value();
        this.metadataVerifier = Objects.requireNonNull(metadataVerifier, "metadataVerifier");
        this.quarantineBudget = Objects.requireNonNull(quarantineBudget, "quarantineBudget");
        this.maskContinuation = Objects.requireNonNull(maskContinuation, "maskContinuation");
    }

    private ManagedContinuationRuntime() {
        enabled = false;
        maxBodyBytes = 0;
        metadataVerifier = null;
        quarantineBudget = null;
        maskContinuation = null;
    }

    public static ManagedContinuationRuntime disabled() {
        return new ManagedContinuationRuntime();
    }

    boolean enabled() {
        return enabled;
    }

    long maxBodyBytes() {
        return maxBodyBytes;
    }

    ManagedMetadataVerifier metadataVerifier() {
        return metadataVerifier;
    }

    QuarantineBudget quarantineBudget() {
        return quarantineBudget;
    }

    MaskContinuationService maskContinuation() {
        return maskContinuation;
    }
}
