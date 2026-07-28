package ai.hamza.scanner;

/**
 * Which scanner produced a {@link ScanFinding}.
 *
 * <ul>
 *   <li>{@link #HAMZA} — Hamza's in-process {@code SecretDetector} (the runtime
 *       enforcement path).</li>
 *   <li>{@link #ORACLE} — the offline oracle used in tooling/tests only,
 *       never on the hot path.</li>
 * </ul>
 *
 * <p>This distinction lives only in the offline {@link ScanFinding} model. It is never
 * a metric label (bounded labels): source does not widen the label space.
 */
public enum ScannerSource {
    HAMZA,
    ORACLE
}
