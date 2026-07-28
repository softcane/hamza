package ai.hamza.masking;

import ai.hamza.adapter.ContentSegment;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MaskPlannerContractTest {

    @Test
    void unionsOverlapsByCodePointWithSecretPriorityAndExactDeduplication() {
        MaskPlanner planner = planner();
        ContentSegment segment = new ContentSegment("segment-0", "🙂ABCDWXYZ!");
        MaskCandidate edm = new MaskCandidate("edm", "edm-customers",
                PlaceholderFamily.EMAIL, "segment-0", 1, 5);
        MaskCandidate secret = new MaskCandidate("secret", "aws-access-token",
                PlaceholderFamily.SECRET, "segment-0", 3, 9);

        MaskPlan plan = planner.plan("scope-1", List.of(segment),
                List.of(edm, secret, secret));

        assertThat(plan.maskedValueCount()).isOne();
        assertThat(plan.edits()).singleElement().satisfies(edit -> {
            assertThat(edit.start()).isEqualTo(2);
            assertThat(edit.end()).isEqualTo(10);
            assertThat(edit.replacement()).matches("<SECRET_[0-9]+>");
        });
    }

    @Test
    void adjacentSpansStaySeparateAndEditsAreOrderedForReverseApplication() {
        MaskPlan plan = planner().plan("scope-1",
                List.of(new ContentSegment("segment-0", "abcdef")),
                List.of(
                        new MaskCandidate("edm", "edm-a", PlaceholderFamily.EMAIL,
                                "segment-0", 3, 6),
                        new MaskCandidate("secret", "secret-a", PlaceholderFamily.SECRET,
                                "segment-0", 0, 3)));

        assertThat(plan.edits()).extracting(edit -> edit.start())
                .containsExactly(0, 3);
    }

    @Test
    void rejectsUnknownSegmentsAndOutOfRangeSpans() {
        MaskPlanner planner = planner();
        List<ContentSegment> segments = List.of(new ContentSegment("segment-0", "abc"));

        assertThatThrownBy(() -> planner.plan("scope-1", segments,
                List.of(new MaskCandidate("secret", "rule", PlaceholderFamily.SECRET,
                        "segment-1", 0, 1))))
                .hasMessageContaining("unknown segment");
        assertThatThrownBy(() -> planner.plan("scope-1", segments,
                List.of(new MaskCandidate("secret", "rule", PlaceholderFamily.SECRET,
                        "segment-0", 0, 4))))
                .hasMessageContaining("outside");
    }

    @Test
    void rejectsInvalidPlannerInputsAndCandidateMetadata() {
        assertThatThrownBy(() -> new MaskPlanner(null)).isInstanceOf(NullPointerException.class);
        MaskPlanner planner = planner();
        assertThatThrownBy(() -> planner.plan("scope-1", List.of(), List.of()))
                .hasMessageContaining("segment count");
        assertThatThrownBy(() -> planner.plan("scope-1", null, List.of()))
                .hasMessageContaining("segment count");
        assertThatThrownBy(() -> planner.plan("scope-1",
                List.of(new ContentSegment("segment-0", "abc")), null))
                .hasMessageContaining("requires an exact Finding");
        assertThatThrownBy(() -> planner.plan("scope-1",
                List.of(new ContentSegment("segment-0", "abc")), List.of()))
                .hasMessageContaining("requires an exact Finding");
        assertThatThrownBy(() -> planner.plan("scope-1",
                List.of(new ContentSegment("segment-0", "abc"),
                        new ContentSegment("segment-0", "def")),
                List.of(new MaskCandidate("secret", "rule", PlaceholderFamily.SECRET,
                        "segment-0", 0, 1))))
                .hasMessageContaining("duplicate content segment");
        assertThatThrownBy(() -> new MaskCandidate("gate", "rule",
                PlaceholderFamily.SECRET, "segment-0", 0, 1))
                .hasMessageContaining("detector");
        assertThatThrownBy(() -> new MaskCandidate("secret", "bad rule",
                PlaceholderFamily.SECRET, "segment-0", 0, 1))
                .hasMessageContaining("rule");
        assertThatThrownBy(() -> new MaskCandidate("secret", "rule",
                null, "segment-0", 0, 1)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new MaskCandidate("secret", "rule",
                PlaceholderFamily.SECRET, "BAD", 0, 1))
                .hasMessageContaining("segment");
        assertThatThrownBy(() -> new MaskCandidate("secret", "rule",
                PlaceholderFamily.SECRET, "segment-0", 1, 1))
                .hasMessageContaining("range");
        assertThatThrownBy(() -> new MaskPlan(List.of(), 1))
                .hasMessageContaining("masked-value count");
    }

    private static MaskPlanner planner() {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, (byte) 7);
        return new MaskPlanner(new MaskScopeStore(
                Clock.systemUTC(), Duration.ofMinutes(15), () -> key));
    }
}
