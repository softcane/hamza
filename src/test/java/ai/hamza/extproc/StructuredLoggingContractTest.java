package ai.hamza.extproc;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Map;

import static ai.hamza.extproc.StructuredEventLogger.Event.DETECTOR_COMPLETED;
import static ai.hamza.extproc.StructuredEventLogger.Event.DETECTOR_GAP;
import static ai.hamza.extproc.StructuredEventLogger.Event.EGRESS_BLOCKED;
import static ai.hamza.extproc.StructuredEventLogger.Event.EGRESS_RELEASED;
import static ai.hamza.extproc.StructuredEventLogger.Event.MASK_APPLIED;
import static ai.hamza.extproc.StructuredEventLogger.Event.MASK_FAILED;
import static ai.hamza.extproc.StructuredEventLogger.Event.MASK_PLANNED;
import static ai.hamza.extproc.StructuredEventLogger.Event.RECORD_COMMITTED;
import static ai.hamza.extproc.StructuredEventLogger.Field.PROVIDER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StructuredLoggingContractTest {

    @Test
    void requiredStableEventsAreAllowlisted() {
        assertThat(Arrays.stream(StructuredEventLogger.Event.values())
                .map(StructuredEventLogger.Event::id))
                .contains(MASK_PLANNED.id(), MASK_APPLIED.id(), MASK_FAILED.id(),
                        DETECTOR_COMPLETED.id(), DETECTOR_GAP.id(), RECORD_COMMITTED.id(),
                        EGRESS_RELEASED.id(), EGRESS_BLOCKED.id());
    }

    @Test
    void unapprovedStringValuesCannotEnterStructuredLogs() {
        StructuredEventLogger logger = StructuredEventLogger.forClass(getClass());
        assertThatThrownBy(() -> logger.info(RECORD_COMMITTED,
                Map.of(PROVIDER, "fake_secret_value")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("provider");
    }

}
