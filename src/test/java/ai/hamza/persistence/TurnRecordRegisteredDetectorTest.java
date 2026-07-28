package ai.hamza.persistence;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.policy.Action;
import ai.hamza.policy.DetectionStatus;
import ai.hamza.policy.DetectorEvidenceFixtures;
import ai.hamza.policy.DetectorRunEvidence;
import ai.hamza.policy.Finding;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * A continuation Record carries one run per <em>registered</em> detector. Secret and
 * EDM are always registered; Presidio only once an operator registers it, so both the
 * two-detector and three-detector shapes must commit.
 */
class TurnRecordRegisteredDetectorTest {

    private static final long BYTES = 128L;

    private static List<DetectorRunEvidence> withPresidio() {
        List<DetectorRunEvidence> runs = new ArrayList<>(DetectorEvidenceFixtures.complete(BYTES));
        runs.add(new DetectorRunEvidence("presidio", "presidio:broad-pii-en:v1",
                DetectionStatus.COMPLETE, Optional.empty(), 1, 1, BYTES, BYTES, 1, 0));
        return List.copyOf(runs);
    }

    private static NormalizedTurn maskedSource() {
        return NormalizedTurn.maskedSource("turn-source", "request-1", "session-1", "codex",
                "openai", "gpt-5-codex",
                List.of(new Finding("presidio", "email-address", Action.MASK)),
                1L, BYTES, java.util.Map.of());
    }

    private static ContinuationEvidence sourceEvidence() {
        return ContinuationEvidence.maskedSource("recovery-1", "synthetic-email", 1,
                "codex-safe", 1, "one-way", "masked-secret-edm", BYTES, 1);
    }

    @Test
    void commitsASourceRecordWithoutPresidioWhenItIsNotRegistered() {
        assertThatCode(() -> new TurnRecord(maskedSource(), sourceEvidence(),
                DetectorEvidenceFixtures.complete(BYTES))).doesNotThrowAnyException();
    }

    @Test
    void commitsASourceRecordWithPresidioOnceItIsRegistered() {
        TurnRecord record = new TurnRecord(maskedSource(), sourceEvidence(), withPresidio());

        assertThat(record.detectorRuns()).extracting(DetectorRunEvidence::detectorId)
                .containsExactlyInAnyOrder("secret", "edm", "presidio");
    }

    @Test
    void refusesARecordThatIsMissingAnAlwaysRegisteredDetector() {
        List<DetectorRunEvidence> secretOnly = List.of(
                DetectorEvidenceFixtures.complete(BYTES).getFirst());

        assertThatThrownBy(() -> new TurnRecord(maskedSource(), sourceEvidence(), secretOnly))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("one run per registered detector");
    }

    @Test
    void refusesADuplicateRunForOneDetector() {
        List<DetectorRunEvidence> duplicated = new ArrayList<>(withPresidio());
        duplicated.add(duplicated.getFirst());

        assertThatThrownBy(() -> new TurnRecord(maskedSource(), sourceEvidence(), duplicated))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("one run per registered detector");
    }

}
