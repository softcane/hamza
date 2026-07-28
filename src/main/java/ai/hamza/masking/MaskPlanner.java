package ai.hamza.masking;

import ai.hamza.adapter.ContentSegment;
import ai.hamza.adapter.ReplacementEdit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Validates, deduplicates, and unions exact code-point spans into Adapter edits. */
public final class MaskPlanner {

    /**
     * Default maskable-segment bound. A default, not a limit: the operator sets the
     * real bound via {@code hamza.continuation.mask.max-segments}. A real Agent Turn
     * carries its whole message history, so it has far more than a handful of
     * segments; too low a bound Blocks every real Turn regardless of body size.
     */
    public static final int DEFAULT_MAX_SEGMENTS = 1_024;

    private final MaskScopeStore scopes;
    private final int maxSegments;

    public MaskPlanner(MaskScopeStore scopes) {
        this(scopes, DEFAULT_MAX_SEGMENTS);
    }

    public MaskPlanner(MaskScopeStore scopes, int maxSegments) {
        this.scopes = Objects.requireNonNull(scopes, "scopes");
        if (maxSegments <= 0) {
            throw new IllegalArgumentException("maxSegments must be positive");
        }
        this.maxSegments = maxSegments;
    }

    public int maxSegments() {
        return maxSegments;
    }

    public MaskPlan plan(String scopeId, List<ContentSegment> segments,
                         List<MaskCandidate> candidates) {
        List<ContentSegment> safeSegments = segments == null ? List.of() : List.copyOf(segments);
        List<MaskCandidate> safeCandidates = candidates == null
                ? List.of() : List.copyOf(candidates);
        if (safeSegments.isEmpty() || safeSegments.size() > maxSegments) {
            throw new IllegalArgumentException("invalid content segment count");
        }
        if (safeCandidates.isEmpty()) {
            throw new IllegalArgumentException("a Mask plan requires an exact Finding");
        }

        Map<String, ContentSegment> byId = new LinkedHashMap<>();
        for (ContentSegment segment : safeSegments) {
            if (byId.putIfAbsent(segment.id(), segment) != null) {
                throw new IllegalArgumentException("duplicate content segment id");
            }
        }

        Map<String, MaskCandidate> unique = new LinkedHashMap<>();
        for (MaskCandidate candidate : safeCandidates) {
            ContentSegment segment = byId.get(candidate.segmentId());
            if (segment == null) {
                throw new IllegalArgumentException("Finding references an unknown segment");
            }
            int codePoints = segment.text().codePointCount(0, segment.text().length());
            if (candidate.end() > codePoints) {
                throw new IllegalArgumentException("Finding span is outside its segment");
            }
            String key = candidate.detectorId() + '\u001f' + candidate.rule() + '\u001f'
                    + candidate.segmentId() + '\u001f' + candidate.start() + '\u001f'
                    + candidate.end();
            unique.putIfAbsent(key, candidate);
        }

        Map<String, List<MaskCandidate>> grouped = new HashMap<>();
        unique.values().forEach(candidate -> grouped
                .computeIfAbsent(candidate.segmentId(), ignored -> new ArrayList<>())
                .add(candidate));

        List<ReplacementEdit> edits = new ArrayList<>();
        for (ContentSegment segment : safeSegments) {
            List<MaskCandidate> found = grouped.get(segment.id());
            if (found == null) {
                continue;
            }
            found.sort(Comparator.comparingInt(MaskCandidate::start)
                    .thenComparingInt(MaskCandidate::end)
                    .thenComparing(MaskCandidate::qualifiedRule));
            int index = 0;
            while (index < found.size()) {
                MaskCandidate strongest = found.get(index);
                int unionStart = strongest.start();
                int unionEnd = strongest.end();
                index++;
                while (index < found.size() && found.get(index).start() < unionEnd) {
                    MaskCandidate overlapping = found.get(index++);
                    unionEnd = Math.max(unionEnd, overlapping.end());
                    strongest = stronger(strongest, overlapping);
                }
                int charStart = segment.text().offsetByCodePoints(0, unionStart);
                int charEnd = segment.text().offsetByCodePoints(0, unionEnd);
                String sourceValue = segment.text().substring(charStart, charEnd);
                String placeholder = scopes.placeholder(scopeId, strongest.family(),
                        strongest.detectorId(), strongest.rule(), sourceValue);
                edits.add(new ReplacementEdit(segment.id(), charStart, charEnd, placeholder));
            }
        }
        edits.sort(Comparator.comparing(ReplacementEdit::segmentId)
                .thenComparingInt(ReplacementEdit::start));
        return new MaskPlan(edits, edits.size());
    }

    private static MaskCandidate stronger(MaskCandidate left, MaskCandidate right) {
        int leftStrength = detectorStrength(left.detectorId());
        int rightStrength = detectorStrength(right.detectorId());
        if (leftStrength != rightStrength) {
            return leftStrength > rightStrength ? left : right;
        }
        return left.qualifiedRule().compareTo(right.qualifiedRule()) <= 0 ? left : right;
    }

    private static int detectorStrength(String detector) {
        return switch (detector) {
            case "secret" -> 3;
            case "edm" -> 2;
            case "presidio" -> 1;
            default -> throw new IllegalArgumentException("unknown detector id");
        };
    }
}
