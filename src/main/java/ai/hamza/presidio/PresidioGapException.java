package ai.hamza.presidio;

import ai.hamza.policy.DetectionReason;
import java.util.Objects;

/**
 * A bounded detector gap. Carries only a fixed reason code: never a response body,
 * matched text, or endpoint detail.
 */
public final class PresidioGapException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final transient DetectionReason reason;

    public PresidioGapException(DetectionReason reason) {
        super(Objects.requireNonNull(reason, "reason").name());
        this.reason = reason;
    }

    public DetectionReason reason() {
        return reason;
    }
}
