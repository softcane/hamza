package ai.hamza.metrics;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.config.HamzaProperties;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Tag;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Metrics contract test: label keys must be bounded — only the keys in
 * the bounded set, never ids, sessions, paths, prompts, or raw inputs — and the expected metric
 * families must be exposed.
 */
class HamzaMetricsContractTest {

    /** The ONLY label keys any Hamza meter may carry. */
    private static final Set<String> ALLOWED_LABEL_KEYS = Set.of(
            "agent", "provider", "model", "status", "kind", "rule", "action",
            "requested", "served", "phase");

    /** Keys Prometheus itself may add to histogram/summary series, also permitted. */
    private static final Set<String> INFRA_LABEL_KEYS = Set.of("le", "quantile");

    private PrometheusMeterRegistry newRegistry() {
        return new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
    }

    private HamzaMetrics metrics(PrometheusMeterRegistry registry) {
        // The context-fill gauge keys on the served model; configure windows for both.
        return new HamzaMetrics(registry, new HamzaProperties(
                new HamzaProperties.Metrics(Map.of("gpt-5-codex", 272000, "gpt-5-mini", 128000)),
                new HamzaProperties.Policy(ai.hamza.policy.Action.FLAG, Map.of(),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, false)));
    }

    private NormalizedTurn sampleTurn() {
        return new NormalizedTurn(
                "turn-1", "sess-1", "codex", "openai", "gpt-5-codex", "gpt-5-mini", "completed",
                120, 20, 100, 80, 30, 200, 1,
                List.of(new Finding("aws-access-key-id", Action.MASK)),
                Action.MASK, 42L, Instant.now());
    }

    private NormalizedTurn noCacheTurn() {
        return new NormalizedTurn(
                "turn-2", "sess-1", "codex", "openai", "gpt-5-codex", "gpt-5-codex", "completed",
                100, 0, 100, 20, 0, 120, 0,
                List.of(), Action.FLAG, 20L, Instant.now());
    }

    @Test
    void everyMeterUsesOnlyBoundedLabelKeys() {
        PrometheusMeterRegistry registry = newRegistry();
        HamzaMetrics metrics = metrics(registry);
        metrics.recordTurn(sampleTurn());
        metrics.recordEgressBlocked("aws-access-key-id");
        metrics.recordStreamError("stream");

        for (Meter meter : registry.getMeters()) {
            String name = meter.getId().getName();
            if (!name.startsWith("hamza")) {
                continue;
            }
            for (Tag tag : meter.getId().getTags()) {
                assertThat(ALLOWED_LABEL_KEYS)
                        .as("meter %s has unexpected label key '%s'", name, tag.getKey())
                        .contains(tag.getKey());
            }
        }
    }

    @Test
    void scrapeExposesExpectedFamiliesAndNoForbiddenLabelKeys() {
        PrometheusMeterRegistry registry = newRegistry();
        HamzaMetrics metrics = metrics(registry);
        metrics.recordTurn(sampleTurn());
        metrics.recordEgressBlocked("aws-access-key-id");
        metrics.recordStreamError("stream");

        String scrape = registry.scrape();

        // Expected families the dashboard depends on.
        assertThat(scrape).contains("hamza_requests_total");
        assertThat(scrape).contains("hamza_tokens_total");
        assertThat(scrape).contains("hamza_request_duration_seconds");
        assertThat(scrape).contains("hamza_model_fallback_total");
        assertThat(scrape).contains("hamza_policy_violations_total");
        assertThat(scrape).contains("hamza_egress_blocked_total");
        assertThat(scrape).contains("hamza_ext_proc_stream_errors_total");
        assertThat(scrape).contains("hamza_context_fill_percent");

        // Token kinds present for the cache-ratio panel.
        assertThat(scrape).contains("kind=\"input\"");
        assertThat(scrape).contains("kind=\"cached\"");

        // Every label key in the exposition for hamza_ families must be on the
        // allowlist (no ids, sessions, paths, prompts, or raw inputs ever leak).
        scrape.lines()
                .filter(l -> l.startsWith("hamza_") && !l.startsWith("# "))
                .forEach(line -> labelKeys(labelsOf(line)).forEach(key ->
                        assertThat(ALLOWED_LABEL_KEYS.contains(key) || INFRA_LABEL_KEYS.contains(key))
                                .as("line carries non-allowlisted label key '%s': %s", key, line)
                                .isTrue()));
    }

    @Test
    void zeroValuedTokenKindsAreExposedForDashboardRatios() {
        PrometheusMeterRegistry registry = newRegistry();
        HamzaMetrics metrics = metrics(registry);
        metrics.recordTurn(noCacheTurn());

        String scrape = registry.scrape();

        assertThat(tokenSample(scrape, "cached")).endsWith(" 0.0");
        assertThat(tokenSample(scrape, "reasoning")).endsWith(" 0.0");
        assertThat(tokenSample(scrape, "input")).endsWith(" 100.0");
        assertThat(tokenSample(scrape, "uncached")).endsWith(" 100.0");
    }

    @Test
    void contextFillSummaryRecordsConfiguredModelPercent() {
        PrometheusMeterRegistry registry = newRegistry();
        HamzaMetrics metrics = metrics(registry);
        metrics.recordTurn(sampleTurn());

        String scrape = registry.scrape();

        assertThat(sampleValue(contextFillSample(scrape, "count"))).isEqualTo(1.0);
        assertThat(sampleValue(contextFillSample(scrape, "sum"))).isEqualTo(0.09375);
    }

    private static String labelsOf(String line) {
        int open = line.indexOf('{');
        int close = line.indexOf('}');
        return (open >= 0 && close > open) ? line.substring(open + 1, close) : "";
    }

    private static List<String> labelKeys(String labels) {
        if (labels.isBlank()) {
            return List.of();
        }
        return List.of(labels.split(",")).stream()
                .map(kv -> kv.contains("=") ? kv.substring(0, kv.indexOf('=')).trim() : kv.trim())
                .toList();
    }

    private static String tokenSample(String scrape, String kind) {
        return scrape.lines()
                .filter(l -> l.startsWith("hamza_tokens_total"))
                .filter(l -> l.contains("kind=\"" + kind + "\""))
                .findFirst()
                .orElseThrow(() -> new AssertionError("missing token kind: " + kind + "\n" + scrape));
    }

    private static String contextFillSample(String scrape, String suffix) {
        return scrape.lines()
                .filter(l -> l.startsWith("hamza_context_fill_percent_" + suffix))
                .filter(l -> l.contains("model=\"gpt-5-mini\""))
                .findFirst()
                .orElseThrow(() -> new AssertionError("missing context fill " + suffix + "\n" + scrape));
    }

    private static double sampleValue(String line) {
        return Double.parseDouble(line.substring(line.lastIndexOf(' ') + 1));
    }
}
