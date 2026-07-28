package ai.hamza.edm;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Accumulates distinct EDM fingerprint matches across the streamed chunks of ONE Turn,
 * so the block threshold applies per Turn, not per scan window: a 12-row
 * dump split 6/6 across a chunk boundary must still block. Confined to a single
 * ext_proc stream's callbacks — no synchronisation needed. Bounded per registry so a
 * pathological Turn cannot grow memory without limit.
 */
public final class EdmTurnAccumulator {

    static final int MAX_PER_REGISTRY = 100_000;

    private final Map<String, Set<Long>> distinct = new LinkedHashMap<>();
    private final Map<String, Set<FullFingerprint>> typedDistinct = new LinkedHashMap<>();
    private EdmScanExhaustionReason exhaustionReason;

    public void add(Map<String, Set<Long>> windowDistinct) {
        windowDistinct.forEach((registry, fingerprints) -> {
            Set<Long> all = distinct.computeIfAbsent(registry, k -> new HashSet<>());
            for (Long fp : fingerprints) {
                if (all.size() >= MAX_PER_REGISTRY) {
                    exhaustionReason = EdmScanExhaustionReason.CANDIDATE_LIMIT;
                    return;
                }
                all.add(fp);
            }
        });
    }

    /** Add one explicit-completeness scan window without hiding exhaustion. */
    public void add(EdmCountScanResult window) {
        add(window.legacyDistinct());
        window.typedDistinct().forEach((registry, fingerprints) -> {
            Set<FullFingerprint> all = typedDistinct.computeIfAbsent(registry, k -> new HashSet<>());
            for (FullFingerprint fingerprint : fingerprints) {
                if (all.size() >= MAX_PER_REGISTRY) {
                    exhaustionReason = EdmScanExhaustionReason.CANDIDATE_LIMIT;
                    return;
                }
                all.add(fingerprint);
            }
        });
        if (!window.complete()) {
            exhaustionReason = window.exhaustionReason()
                    .orElse(EdmScanExhaustionReason.CANDIDATE_LIMIT);
        }
    }

    /** Registry name → distinct matches across all chunks seen so far. Content-free. */
    public Map<String, Integer> counts() {
        Map<String, Integer> counts = new LinkedHashMap<>(EdmMatcher.counts(distinct));
        EdmMatcher.counts(typedDistinct).forEach((registry, count) ->
                counts.merge(registry, count, Math::max));
        return Map.copyOf(counts);
    }

    public boolean complete() {
        return exhaustionReason == null;
    }

    public java.util.Optional<EdmScanExhaustionReason> exhaustionReason() {
        return java.util.Optional.ofNullable(exhaustionReason);
    }

    public Set<String> typedRegistryIds() {
        return Set.copyOf(typedDistinct.keySet());
    }
}
