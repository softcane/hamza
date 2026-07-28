package ai.hamza.scanner;

/**
 * How confident a scanner rule is that a match is a real credential. Drives the safe
 * default Action for imported/oracle rules: only {@link #HIGH} confidence rules are
 * candidates for promotion beyond {@code FLAG} (PRD: high-confidence secrets can block
 * while noisy rules only flag).
 */
public enum Confidence {
    HIGH,
    MEDIUM,
    LOW
}
