package ai.hamza.policy;

/**
 * A single result of inspecting Egress (CONTEXT glossary: <em>Finding</em>) — e.g. a
 * detected secret. A Turn can have many Findings.
 *
 * <p>Content-free by invariant: a Finding holds the {@code rule}
 * that matched and the {@link Action} taken, <strong>never</strong> the matched
 * secret value.
 */
public record Finding(String detector, String rule, Action action) {

    public Finding(String rule, Action action) {
        this("gate", rule, action);
    }

    public Finding {
        if (detector == null || !detector.matches("secret|edm|presidio|gate")) {
            throw new IllegalArgumentException("unknown detector id");
        }
        if (rule == null || rule.isBlank() || rule.length() > 128
                || !rule.matches("[A-Za-z0-9][A-Za-z0-9._:-]*")) {
            throw new IllegalArgumentException("rule must be a bounded identifier");
        }
        if (action == null) {
            throw new IllegalArgumentException("action is required");
        }
    }
}
