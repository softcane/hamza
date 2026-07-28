package ai.hamza.edm;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Complete-or-exhausted typed EDM scan result for Safe Continuation. */
public final class EdmScanResult {

    private final List<EdmMatch> matches;
    private final Map<String, Integer> distinctCounts;
    private final EdmScanExhaustionReason exhaustionReason;
    private final int candidatesExamined;

    EdmScanResult(List<EdmMatch> matches, Map<String, Integer> distinctCounts,
                  EdmScanExhaustionReason exhaustionReason, int candidatesExamined) {
        this.matches = List.copyOf(matches);
        this.distinctCounts = Map.copyOf(new LinkedHashMap<>(distinctCounts));
        this.exhaustionReason = exhaustionReason;
        this.candidatesExamined = candidatesExamined;
    }

    public boolean complete() {
        return exhaustionReason == null;
    }

    public List<EdmMatch> matches() {
        return matches;
    }

    public Map<String, Integer> distinctCounts() {
        return distinctCounts;
    }

    public Optional<EdmScanExhaustionReason> exhaustionReason() {
        return Optional.ofNullable(exhaustionReason);
    }

    public int candidatesExamined() {
        return candidatesExamined;
    }

    @Override
    public String toString() {
        return "EdmScanResult[complete=" + complete() + ", matches=" + matches.size()
                + ", registries=" + distinctCounts.size() + ", candidates="
                + candidatesExamined + "]";
    }
}
