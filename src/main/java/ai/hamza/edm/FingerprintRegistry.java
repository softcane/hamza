package ai.hamza.edm;

import java.util.Set;

/**
 * One named fingerprint set produced by the in-boundary indexer over one sensitive
 * store (e.g. {@code customers}). Holds ONLY salted one-way fingerprints — the Gate
 * could not reconstruct the underlying values. The salt lives
 * here because the Gate must fingerprint egress candidates the same way; that permits
 * on-gate dictionary probing of *guessed* values, an accepted v1 residual.
 *
 * @param name         registry name; becomes the content-free Finding rule
 *                     {@code edm-<name>}, so keep it label-safe (lowercase, dashes)
 * @param salt         per-registry HMAC salt (rotate by re-indexing + re-pushing)
 * @param fingerprints the salted 64-bit value fingerprints
 */
public record FingerprintRegistry(String name, byte[] salt, Set<Long> fingerprints) {

    /** True when the normalized candidate is literally a value from this registry. */
    public boolean contains(String normalizedCandidate) {
        return fingerprints.contains(Fingerprinter.fingerprint(salt, normalizedCandidate));
    }
}
