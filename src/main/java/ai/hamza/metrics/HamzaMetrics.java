package ai.hamza.metrics;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.config.HamzaProperties;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Locale;
import java.util.Map;

/**
 * Micrometer meters with <strong>bounded labels only</strong> (the bounded label set / the content-free invariant). The only
 * permitted label keys are: agent, provider, model, status, kind, rule, action,
 * requested, served, phase. Never ids, cwd, prompts, or raw inputs.
 *
 * <p>Meter names are dot-cased; the Prometheus registry renders them as the families
 * named in the bounded set (e.g. {@code hamza.requests} → {@code hamza_requests_total}).
 */
@Component
public class HamzaMetrics {

    private final MeterRegistry registry;
    private final Map<String, Integer> modelContextTokens;

    public HamzaMetrics(MeterRegistry registry, HamzaProperties properties) {
        this.registry = registry;
        this.modelContextTokens = properties.metrics().modelContextTokens();
    }

    /** Emit all per-Turn meters from a finalized, content-free {@link NormalizedTurn}. */
    public void recordTurn(NormalizedTurn t) {
        String model = modelLabel(t);
        Tags base = Tags.of("agent", t.agent(), "provider", t.provider(), "model", model);

        registry.counter("hamza.requests", base.and("status", nullSafe(t.status()))).increment();

        Timer.builder("hamza.request.duration")
                .tags(base)
                .register(registry)
                .record(Duration.ofMillis(t.durationMs()));

        token(base, "input", t.inputTokens());
        token(base, "cached", t.cachedInputTokens());
        token(base, "uncached", t.uncachedInputTokens());
        token(base, "output", t.outputTokens());
        token(base, "reasoning", t.reasoningTokens());

        if (t.isModelFallback()) {
            registry.counter("hamza.model.fallback",
                    "requested", nullSafe(t.requestedModel()),
                    "served", nullSafe(t.servedModel())).increment();
        }

        recordContextFill(t, model);

        for (Finding f : t.findings()) {
            registry.counter("hamza.policy.violations",
                    "rule", f.rule(), "action", f.action().name()).increment();
        }
    }

    /** A hard Block of Egress ({@code hamza_egress_blocked_total}). */
    public void recordEgressBlocked(String rule) {
        registry.counter("hamza.egress.blocked", "rule", rule).increment();
    }

    /** An ext_proc stream error, labelled by the phase it occurred in. */
    public void recordStreamError(String phase) {
        registry.counter("hamza.ext.proc.stream.errors", "phase", phase).increment();
    }

    /** Count the immutable source Block and derived Flag as separate Turns. */
    public void recordContinuationTurn(ContinuationTurnKind kind, Action action) {
        registry.counter("hamza.continuation.turns",
                "kind", label(kind), "action", java.util.Objects.requireNonNull(action).name())
                .increment();
    }

    /** Count one bounded intervention disposition; no task or recovery identity is accepted. */
    public void recordContinuationStatus(ContinuationStatus status) {
        registry.counter("hamza.continuation.interventions", "status", label(status)).increment();
    }

    /** Content-free byte accounting for withheld, inspected, and Egressed bodies. */
    public void recordContinuationBytes(ContinuationByteKind kind, long bytes) {
        if (bytes < 0) {
            throw new IllegalArgumentException("continuation bytes must be non-negative");
        }
        var counter = registry.counter("hamza.continuation.bytes", "kind", label(kind));
        if (bytes > 0) {
            counter.increment(bytes);
        }
    }

    /** Record bounded local processing time. Provider latency is not a readiness signal. */
    public void recordContinuationDuration(ContinuationPhase phase, Duration duration) {
        if (duration == null || duration.isNegative()) {
            throw new IllegalArgumentException("continuation duration must be non-negative");
        }
        Timer.builder("hamza.continuation.duration")
                .tag("phase", label(phase))
                .register(registry)
                .record(duration);
    }

    /** Explicit scan exhaustion, retaining only its bounded phase and existing Action. */
    public void recordContinuationScanIncomplete(ContinuationPhase phase, Action action) {
        registry.counter("hamza.continuation.scan.incomplete",
                "phase", label(phase), "action", java.util.Objects.requireNonNull(action).name())
                .increment();
    }

    private void token(Tags base, String kind, long count) {
        var counter = registry.counter("hamza.tokens", base.and("kind", kind));
        if (count > 0) {
            counter.increment(count);
        }
    }

    private void recordContextFill(NormalizedTurn t, String model) {
        Integer window = modelContextTokens.get(model);
        if (window == null || window <= 0 || t.inputTokens() <= 0) {
            return; // never fabricate a context window
        }
        double percent = Math.min(100.0, (t.inputTokens() * 100.0) / window);
        registry.summary("hamza.context.fill.percent", "agent", t.agent(), "model", model)
                .record(percent);
    }

    private static String modelLabel(NormalizedTurn t) {
        if (t.servedModel() != null) {
            return t.servedModel();
        }
        return t.requestedModel() != null ? t.requestedModel() : "unknown";
    }

    private static String nullSafe(String s) {
        return s == null ? "unknown" : s;
    }

    private static String label(Enum<?> value) {
        return java.util.Objects.requireNonNull(value, "metric value")
                .name().toLowerCase(Locale.ROOT);
    }

    public enum ContinuationTurnKind {
        SOURCE,
        DERIVED
    }

    public enum ContinuationStatus {
        ELIGIBLE,
        ATTEMPTED,
        DELIVERED,
        REJECTED,
        FAILED_CLOSED,
        FALLBACK,
        COMPLETED,
        FAILED,
        HUMAN_FALLBACK
    }

    public enum ContinuationByteKind {
        WITHHELD,
        INSPECTED,
        EGRESSED
    }

    public enum ContinuationPhase {
        QUARANTINE,
        SOURCE_SCAN,
        TRANSFORMATION,
        FINAL_SCAN
    }
}
