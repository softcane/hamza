package ai.hamza.masking;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.persistence.ContinuationEvidence;
import ai.hamza.persistence.TurnRecord;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MaskEvidenceContractTest {

    @Test
    void linkedSourceAndDerivedRecordsRemainContentFree() {
        var runs = List.of(
                new ai.hamza.policy.DetectorRunEvidence(
                        "secret", "rulepack-v1", ai.hamza.policy.DetectionStatus.COMPLETE,
                        java.util.Optional.empty(), 1, 1, 64, 64, 1, 1),
                new ai.hamza.policy.DetectorRunEvidence(
                        "edm", "edm-v1", ai.hamza.policy.DetectionStatus.COMPLETE,
                        java.util.Optional.empty(), 1, 1, 64, 64, 1, 0));
        NormalizedTurn source = NormalizedTurn.maskedSource(
                "source-1", "request-1", "scope-1", "codex", "openai", "gpt-5-codex",
                List.of(new Finding("secret", "aws-access-token", Action.MASK)),
                2, 64, Map.of());
        TurnRecord sourceRecord = new TurnRecord(source, ContinuationEvidence.maskedSource(
                "scope-1", "mask-email", 1, "profile", 1, "one-way",
                "masked-secret-edm", 64, 1), runs);
        NormalizedTurn derived = new NormalizedTurn(
                "derived-1", "scope-1", "codex", "openai", "gpt-5-codex",
                null, "completed", 0, 0, 0, 0, 0, 0, 0, List.of(), Action.FLAG,
                3, Instant.parse("2026-07-15T00:00:00Z"), "request-1",
                48L, 48L, 48L, Map.of());
        TurnRecord derivedRecord = new TurnRecord(derived,
                ContinuationEvidence.derived("scope-1", "source-1"), runs);

        assertThat(sourceRecord.turn().action()).isEqualTo(Action.MASK);
        assertThat(sourceRecord.turn().requestBytesEgressed()).isZero();
        assertThat(sourceRecord.continuation().maskedValueCount()).isOne();
        assertThat(derivedRecord.continuation().parentTurnId()).isEqualTo("source-1");
        assertThat(derivedRecord.turn().requestBytesEgressed()).isEqualTo(48L);
        assertThat(sourceRecord.toString() + derivedRecord)
                .doesNotContain(MaskingTestFixture.EMAIL, MaskingTestFixture.SECRET,
                        "<SECRET_", "<EMAIL_");
    }
}
