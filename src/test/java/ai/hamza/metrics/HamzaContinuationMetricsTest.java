package ai.hamza.metrics;

import ai.hamza.config.HamzaProperties;
import ai.hamza.policy.Action;
import io.micrometer.core.instrument.Meter;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class HamzaContinuationMetricsTest {

    private static final Set<String> ALLOWED_LABEL_KEYS = Set.of(
            "agent", "provider", "model", "status", "kind", "rule", "action",
            "requested", "served", "phase");

    @Test
    void recordsBoundedContinuationOutcomesBytesAndPhaseTimeWithoutIdentifiers() {
        PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
        HamzaMetrics metrics = new HamzaMetrics(registry,
                new HamzaProperties(null, null, null, null, null));

        metrics.recordContinuationTurn(HamzaMetrics.ContinuationTurnKind.SOURCE, Action.MASK);
        metrics.recordContinuationTurn(HamzaMetrics.ContinuationTurnKind.DERIVED, Action.FLAG);
        metrics.recordContinuationStatus(HamzaMetrics.ContinuationStatus.DELIVERED);
        metrics.recordContinuationStatus(HamzaMetrics.ContinuationStatus.ELIGIBLE);
        metrics.recordContinuationStatus(HamzaMetrics.ContinuationStatus.REJECTED);
        metrics.recordContinuationStatus(HamzaMetrics.ContinuationStatus.FAILED_CLOSED);
        metrics.recordContinuationBytes(HamzaMetrics.ContinuationByteKind.WITHHELD, 512);
        metrics.recordContinuationBytes(HamzaMetrics.ContinuationByteKind.INSPECTED, 384);
        metrics.recordContinuationBytes(HamzaMetrics.ContinuationByteKind.EGRESSED, 384);
        metrics.recordContinuationDuration(HamzaMetrics.ContinuationPhase.FINAL_SCAN,
                Duration.ofMillis(12));
        metrics.recordContinuationScanIncomplete(HamzaMetrics.ContinuationPhase.SOURCE_SCAN,
                Action.BLOCK);

        for (Meter meter : registry.getMeters()) {
            if (meter.getId().getName().startsWith("hamza.continuation")) {
                assertThat(meter.getId().getTags())
                        .allSatisfy(tag -> assertThat(ALLOWED_LABEL_KEYS).contains(tag.getKey()));
            }
        }
        String scrape = registry.scrape();
        assertThat(scrape)
                .contains("hamza_continuation_turns_total")
                .contains("hamza_continuation_interventions_total")
                .contains("hamza_continuation_bytes_total")
                .contains("hamza_continuation_duration_seconds")
                .contains("hamza_continuation_scan_incomplete_total")
                .contains("action=\"MASK\",kind=\"source\"")
                .contains("action=\"FLAG\",kind=\"derived\"")
                .contains("status=\"delivered\"")
                .contains("status=\"eligible\"")
                .contains("status=\"rejected\"")
                .contains("status=\"failed_closed\"")
                .doesNotContain("registry", "field", "recipe", "recovery", "customers",
                        "example.invalid", "gpt-5-codex");
    }
}
