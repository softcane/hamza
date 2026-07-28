package ai.hamza.attest;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RecordHasherVersionCompatibilityTest {

    @Test
    void v2AndV3CanonicalHashesRemainByteIdentical() {
        var v2 = turn(RecordHasher.LEGACY_RECORD_VERSION, null);
        var v3 = turn(RecordHasher.REQUEST_ID_RECORD_VERSION, "request-1");

        assertThat(RecordHasher.entryHash(RecordHasher.GENESIS, v2))
                .isEqualTo("02f2c849fd18f7d85279c2c37fceadbb070346be8bc54295b453150aa9654a2c");
        assertThat(RecordHasher.entryHash(RecordHasher.GENESIS, v3))
                .isEqualTo("12d49e82a37def972e4bd693452424f13389fa0f3bcaa79c7ca7cdb45a153af5");
    }

    @Test
    void v4CommitsToContinuationByteAccountingAndEdmEvents() {
        var continuation = new RecordHasher.ContinuationHashFields(
                "SOURCE", "recovery-1", null, "synthetic-email", 1,
                "repo-safe-edit", 1, "ATTEMPTED", "eligible-edm",
                "one-way", "UNVERIFIED", 128L);
        var v4 = new RecordHasher.HashableTurn(
                RecordHasher.CONTINUATION_RECORD_VERSION, "source-1", "request-1", "scope",
                "codex", "openai", "gpt-5-codex", null, "blocked",
                0, 0, 0, 0, 0, 0, 0, "BLOCK", 4,
                "2026-07-11T10:00:00Z", "BLOCK", "test-fingerprint",
                128L, 128L, 0L, continuation,
                List.of(RecordHasher.edmEventKey("customers", 1, "BLOCK")),
                List.of(RecordHasher.findingKey("edm-customers", "BLOCK")));

        String original = RecordHasher.entryHash(RecordHasher.GENESIS, v4);
        var editedBytes = new RecordHasher.HashableTurn(
                v4.hashVersion(), v4.turnId(), v4.requestId(), v4.sessionId(), v4.agent(),
                v4.provider(), v4.requestedModel(), v4.servedModel(), v4.status(),
                v4.inputTokens(), v4.cachedInputTokens(), v4.uncachedInputTokens(),
                v4.outputTokens(), v4.reasoningTokens(), v4.totalTokens(), v4.toolCalls(),
                v4.action(), v4.durationMs(), v4.ts(), v4.posture(), v4.configFingerprint(),
                128L, 128L, 1L, v4.continuation(), v4.edmEventKeys(), v4.findingKeys());

        assertThat(RecordHasher.CONTINUATION_RECORD_VERSION).isEqualTo("hamza-record/v4");
        assertThat(original)
                .isEqualTo("8e15d088acbe4b48d1eeb327ddfdb25ed530d4ee422ea34864709ea4526ac63f");
        assertThat(RecordHasher.entryHash(RecordHasher.GENESIS, editedBytes)).isNotEqualTo(original);
    }

    private static RecordHasher.HashableTurn turn(String version, String requestId) {
        return new RecordHasher.HashableTurn(version, "v2-turn", requestId, "sess", "codex",
                "openai", "gpt-5-codex", "gpt-5-codex", "completed",
                10, 0, 10, 5, 0, 15, 0, "FLAG", 5,
                "2026-07-06T10:00:00Z", "FLAG", "test-fingerprint", List.of());
    }
}
