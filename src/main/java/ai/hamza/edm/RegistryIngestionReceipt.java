package ai.hamza.edm;

/**
 * Content-free receipt for one Registry push. It is safe to hand to an operator:
 * counts and a version digest only, never raw values, salt, or per-value mappings.
 */
public record RegistryIngestionReceipt(String registry, String version, long valuesSeen,
                                       long indexed, long droppedWeak,
                                       long distinctFingerprints) {
}
