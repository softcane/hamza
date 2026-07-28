package ai.hamza.scanner;

import ai.hamza.policy.SecretDetector;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Compares Hamza's in-process detector against the offline oracle over the same
 * Egress body, and deduplicates findings that resolve to the same stable rule (GrillMe
 * Q18). Offline tooling/tests only — it never runs on the hot path.
 *
 * <p>The comparison surfaces <em>coverage gaps</em> (rules Oracle found that Hamza
 * missed) so we can decide which high-confidence rules to import into the detector.
 */
@Component
public class ScannerComparison {

    /**
     * Coverage comparison for one body, by stable rule id.
     *
     * @param agreed        rules both scanners flagged
     * @param hamzaOnly     rules only Hamza's detector flagged
     * @param oracleOnly  rules only Oracle flagged (candidate coverage gaps to import)
     */
    public record Comparison(List<String> agreed, List<String> hamzaOnly, List<String> oracleOnly) {
        public Comparison {
            agreed = List.copyOf(agreed);
            hamzaOnly = List.copyOf(hamzaOnly);
            oracleOnly = List.copyOf(oracleOnly);
        }

        public boolean hasCoverageGap() {
            return !oracleOnly.isEmpty();
        }
    }

    /** Lift Hamza detector matches into the normalised model (native rules are HIGH confidence). */
    public List<ScanFinding> fromDetector(List<SecretDetector.Match> matches) {
        List<ScanFinding> out = new ArrayList<>(matches.size());
        for (SecretDetector.Match m : matches) {
            out.add(ScanFinding.hamza(m.rule(), new Span(m.start(), m.end()), Confidence.HIGH));
        }
        return out;
    }

    /**
     * Deduplicate findings that resolve to the same stable rule and overlapping span. When
     * a Hamza finding (with a span, redactable) and a Oracle finding (no span) collide on
     * the same rule id, the redactable Hamza finding is kept so enforcement stays exact.
     */
    public List<ScanFinding> deduplicate(List<ScanFinding> findings) {
        List<ScanFinding> kept = new ArrayList<>();
        for (ScanFinding candidate : findings) {
            Optional<Integer> dupIndex = indexOfDuplicate(kept, candidate);
            if (dupIndex.isEmpty()) {
                kept.add(candidate);
                continue;
            }
            int i = dupIndex.get();
            if (prefer(candidate, kept.get(i))) {
                kept.set(i, candidate);
            }
        }
        return kept;
    }

    /** Compare coverage by stable rule id (dedup within each source first). */
    public Comparison compare(List<ScanFinding> hamzaFindings, List<ScanFinding> oracleFindings) {
        Set<String> hamza = stableRuleIds(hamzaFindings);
        Set<String> oracle = stableRuleIds(oracleFindings);

        List<String> agreed = new ArrayList<>();
        List<String> hamzaOnly = new ArrayList<>();
        for (String id : hamza) {
            (oracle.contains(id) ? agreed : hamzaOnly).add(id);
        }
        List<String> oracleOnly = new ArrayList<>();
        for (String id : oracle) {
            if (!hamza.contains(id)) {
                oracleOnly.add(id);
            }
        }
        return new Comparison(agreed, hamzaOnly, oracleOnly);
    }

    private static Optional<Integer> indexOfDuplicate(List<ScanFinding> kept, ScanFinding candidate) {
        for (int i = 0; i < kept.size(); i++) {
            if (isDuplicate(kept.get(i), candidate)) {
                return Optional.of(i);
            }
        }
        return Optional.empty();
    }

    /** Same secret iff same stable rule and either lacks a span or the spans overlap. */
    private static boolean isDuplicate(ScanFinding a, ScanFinding b) {
        if (!a.ruleId().equals(b.ruleId())) {
            return false;
        }
        if (a.span().isEmpty() || b.span().isEmpty()) {
            return true; // same rule, at least one span-less: treat as the same leak
        }
        return a.span().get().overlaps(b.span().get());
    }

    /** Prefer the redactable finding (has a span); otherwise keep the incumbent. */
    private static boolean prefer(ScanFinding candidate, ScanFinding incumbent) {
        return candidate.canRedact() && !incumbent.canRedact();
    }

    private static Set<String> stableRuleIds(List<ScanFinding> findings) {
        Set<String> ids = new LinkedHashSet<>();
        for (ScanFinding f : findings) {
            ids.add(f.ruleId());
        }
        return ids;
    }
}
