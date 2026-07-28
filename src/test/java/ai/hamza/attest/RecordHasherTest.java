package ai.hamza.attest;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Canonicalization invariants: separator characters in
 * client-influenced fields (e.g. requestedModel from the request JSON) must not let two
 * DIFFERENT field tuples hash identically — that would be an undetectable edit in the
 * exact layer built to detect edits.
 */
class RecordHasherTest {

    private static RecordHasher.HashableTurn turn(String requestedModel, String servedModel,
                                                  String sessionId) {
        return new RecordHasher.HashableTurn(
                "t1", sessionId, "codex", "openai", requestedModel, servedModel,
                "completed", 10, 0, 10, 5, 0, 15, 0, "FLAG", 5,
                "2026-07-06T10:00:00Z", "FLAG", "fp", List.of());
    }

    @Test
    void fieldSeparatorInAValueCannotShiftTheFieldBoundary() {
        // Without escaping these two tuples concatenate to identical canonical bytes
        // ("m" FS "X" FS "s"): one FS from the value, one from the joiner.
        var boundaryInModel = turn("m\u001fX", "s", "sess");
        var boundaryInServed = turn("m", "X\u001fs", "sess");
        String prev = RecordHasher.GENESIS;
        assertThat(RecordHasher.entryHash(prev, boundaryInModel))
                .isNotEqualTo(RecordHasher.entryHash(prev, boundaryInServed));
    }

    @Test
    void findingKeySeparatorCannotBeForgedFromARuleName() {
        assertThat(RecordHasher.findingKey("a\u001db", "BLOCK"))
                .isNotEqualTo(RecordHasher.findingKey("a", "b\u001dBLOCK"));
    }

    @Test
    void nullFieldAndLiteralSentinelStringHashDifferently() {
        var nullSession = turn("m", "s", null);
        var sentinelLookalike = turn("m", "s", "\u0000null");
        String prev = RecordHasher.GENESIS;
        assertThat(RecordHasher.entryHash(prev, nullSession))
                .isNotEqualTo(RecordHasher.entryHash(prev, sentinelLookalike));
    }

    @Test
    void escapingIsDeterministic() {
        var t = turn("m\u001fX\\weird", "s", "sess");
        assertThat(RecordHasher.entryHash(RecordHasher.GENESIS, t))
                .isEqualTo(RecordHasher.entryHash(RecordHasher.GENESIS, t));
    }
}
