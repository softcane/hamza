package ai.hamza.policy;

/**
 * What the Gate does about a Turn's Findings (CONTEXT glossary: <em>Action</em>):
 * <ul>
 *   <li>{@link #FLAG} — record only (the default Posture: observe before enforce).</li>
 *   <li>{@link #MASK} — mutate the body before it leaves.</li>
 *   <li>{@link #BLOCK} — stop the request.</li>
 * </ul>
 */
public enum Action {
    FLAG,
    MASK,
    BLOCK
}
