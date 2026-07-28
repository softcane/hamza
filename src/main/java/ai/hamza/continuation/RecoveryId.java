package ai.hamza.continuation;

import java.util.regex.Pattern;

/** Opaque, bounded recovery-scope identifier. */
public final class RecoveryId {

    private static final Pattern FORMAT = Pattern.compile("[A-Za-z0-9_-]{16,96}");
    private final String value;

    private RecoveryId(String value) {
        this.value = value;
    }

    public static RecoveryId parse(String value) {
        if (value == null || !FORMAT.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid recovery id");
        }
        return new RecoveryId(value);
    }

    /** Explicit access for internal metadata and causal Record linkage only. */
    public String value() {
        return value;
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof RecoveryId id && value.equals(id.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return "<recovery-id>";
    }
}
