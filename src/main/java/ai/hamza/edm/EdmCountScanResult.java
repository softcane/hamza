package ai.hamza.edm;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Complete-or-exhausted content-free EDM count scan used by policy evaluation. */
public final class EdmCountScanResult {

    private final Map<String, Set<Long>> legacyDistinct;
    private final Map<String, Set<FullFingerprint>> typedDistinct;
    private final Map<String, Integer> counts;
    private final EdmScanExhaustionReason exhaustionReason;
    private final int candidatesExamined;

    EdmCountScanResult(Map<String, Set<Long>> legacyDistinct,
                       Map<String, Set<FullFingerprint>> typedDistinct,
                       EdmScanExhaustionReason exhaustionReason,
                       int candidatesExamined) {
        this.legacyDistinct = immutableSets(legacyDistinct);
        this.typedDistinct = immutableSets(typedDistinct);
        Map<String, Integer> merged = new LinkedHashMap<>();
        this.legacyDistinct.forEach((registry, values) -> merged.put(registry, values.size()));
        this.typedDistinct.forEach((registry, values) ->
                merged.merge(registry, values.size(), Math::max));
        this.counts = Map.copyOf(merged);
        this.exhaustionReason = exhaustionReason;
        this.candidatesExamined = candidatesExamined;
    }

    public boolean complete() {
        return exhaustionReason == null;
    }

    public Map<String, Integer> counts() {
        return counts;
    }

    public Optional<EdmScanExhaustionReason> exhaustionReason() {
        return Optional.ofNullable(exhaustionReason);
    }

    public int candidatesExamined() {
        return candidatesExamined;
    }

    /** Registry ids with at least one v2 full-width match in this scan. */
    public Set<String> typedRegistryIds() {
        return typedDistinct.keySet();
    }

    Map<String, Set<Long>> legacyDistinct() {
        return legacyDistinct;
    }

    Map<String, Set<FullFingerprint>> typedDistinct() {
        return typedDistinct;
    }

    private static <T> Map<String, Set<T>> immutableSets(Map<String, Set<T>> input) {
        Map<String, Set<T>> copy = new LinkedHashMap<>();
        input.forEach((registry, values) ->
                copy.put(registry, Set.copyOf(new LinkedHashSet<>(values))));
        return Map.copyOf(copy);
    }

    @Override
    public String toString() {
        return "EdmCountScanResult[complete=" + complete() + ", registries=" + counts.size()
                + ", candidates=" + candidatesExamined + "]";
    }
}
