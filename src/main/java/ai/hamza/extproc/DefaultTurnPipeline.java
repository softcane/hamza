package ai.hamza.extproc;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.adapter.ProviderAdapter;
import ai.hamza.config.HamzaProperties;
import ai.hamza.edm.EdmTurnAccumulator;
import ai.hamza.metrics.HamzaMetrics;
import ai.hamza.persistence.ContinuationEvidence;
import ai.hamza.persistence.TurnRecord;
import ai.hamza.persistence.TurnRepository;
import ai.hamza.policy.Action;
import ai.hamza.policy.DetectorRunEvidence;
import ai.hamza.policy.DetectionReason;
import ai.hamza.policy.DetectionStatus;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.PolicyResult;
import ai.hamza.policy.SecretDetector;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static ai.hamza.extproc.StructuredEventLogger.Event.DETECTOR_COMPLETED;
import static ai.hamza.extproc.StructuredEventLogger.Event.DETECTOR_GAP;
import static ai.hamza.extproc.StructuredEventLogger.Event.EGRESS_BLOCKED;
import static ai.hamza.extproc.StructuredEventLogger.Event.EGRESS_RELEASED;
import static ai.hamza.extproc.StructuredEventLogger.Event.MASK_PLANNED;
import static ai.hamza.extproc.StructuredEventLogger.Event.RECORD_COMMITTED;
import static ai.hamza.extproc.StructuredEventLogger.Field.ACTION;
import static ai.hamza.extproc.StructuredEventLogger.Field.COUNT;
import static ai.hamza.extproc.StructuredEventLogger.Field.DETECTOR;
import static ai.hamza.extproc.StructuredEventLogger.Field.DURATION_MICROS;
import static ai.hamza.extproc.StructuredEventLogger.Field.PROVIDER;
import static ai.hamza.extproc.StructuredEventLogger.Field.REASON;
import static ai.hamza.extproc.StructuredEventLogger.Field.STATUS;
import static ai.hamza.extproc.StructuredEventLogger.Field.TURN_ID;

/** Default in-process implementation of the typed Turn pipeline. */
@Component
public final class DefaultTurnPipeline implements TurnPipeline {

    private static final StructuredEventLogger events =
            StructuredEventLogger.forClass(DefaultTurnPipeline.class);

    private final PolicyEngine policy;
    private final TurnRepository records;
    private final HamzaMetrics metrics;
    private final List<ProviderAdapter> adapters;
    private final CoachSessionTracker coachSessions;
    private final ReEncodedContentDetector reEncoded;
    private final int maxBodyBytes;
    private final List<String> controlPlanePaths;
    private final boolean streamOversize;
    private final ManagedContinuationRuntime managedRuntime;

    @Autowired
    public DefaultTurnPipeline(List<ProviderAdapter> adapters, PolicyEngine policy,
                               TurnRepository records, HamzaMetrics metrics,
                               CoachSessionTracker coachSessions,
                               ReEncodedContentDetector reEncoded,
                               HamzaProperties properties,
                               Optional<ManagedContinuationRuntime> managedRuntime) {
        this(adapters, policy, records, metrics, coachSessions, reEncoded,
                properties.policy().maxBodyBytes(), properties.policy().controlPlanePaths(),
                properties.policy().streamOversize(),
                managedRuntime.orElseGet(ManagedContinuationRuntime::disabled));
    }

    DefaultTurnPipeline(PolicyEngine policy, TurnRepository records, HamzaMetrics metrics) {
        this(List.of(), policy, records, metrics, new CoachSessionTracker(),
                new ReEncodedContentDetector(), HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, false,
                ManagedContinuationRuntime.disabled());
    }

    DefaultTurnPipeline(List<ProviderAdapter> adapters, PolicyEngine policy,
                        TurnRepository records, HamzaMetrics metrics,
                        CoachSessionTracker coachSessions, ReEncodedContentDetector reEncoded,
                        int maxBodyBytes, List<String> controlPlanePaths, boolean streamOversize,
                        ManagedContinuationRuntime managedRuntime) {
        this.policy = policy;
        this.records = records;
        this.metrics = metrics;
        this.adapters = adapters == null ? List.of() : List.copyOf(adapters);
        this.coachSessions = coachSessions == null ? new CoachSessionTracker() : coachSessions;
        this.reEncoded = reEncoded == null ? new ReEncodedContentDetector() : reEncoded;
        this.maxBodyBytes = maxBodyBytes > 0
                ? maxBodyBytes : HamzaProperties.DEFAULT_MAX_BODY_BYTES;
        this.controlPlanePaths = controlPlanePaths == null
                ? HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS : List.copyOf(controlPlanePaths);
        this.streamOversize = streamOversize;
        this.managedRuntime = managedRuntime == null
                ? ManagedContinuationRuntime.disabled() : managedRuntime;
    }

    @Override
    public Session openSession(boolean coachEnabled) {
        return new DefaultTurnPipelineSession(adapters, this, coachSessions, reEncoded,
                maxBodyBytes, controlPlanePaths, streamOversize, managedRuntime,
                coachEnabled);
    }

    @Override
    public PolicyResult inspect(byte[] body) {
        return observed(policy.evaluate(body));
    }

    @Override
    public PolicyResult inspectPrefix(byte[] body) {
        return observed(policy.evaluatePrefix(body));
    }

    @Override
    public PolicyResult inspectStream(byte[] window, EdmTurnAccumulator accumulator) {
        return observed(policy.evaluateStreamChunk(window, accumulator));
    }

    @Override
    public List<DetectorRunEvidence> upstreamBlockEvidence(long receivedBytes) {
        long boundedBytes = Math.max(0L, receivedBytes);
        return List.of(
                skipped("secret", SecretDetector.DETECTOR_VERSION, boundedBytes),
                skipped("edm", "edm-v1", boundedBytes));
    }

    private static DetectorRunEvidence skipped(String detector, String version,
                                               long receivedBytes) {
        return new DetectorRunEvidence(detector, version, DetectionStatus.SKIPPED,
                Optional.of(DetectionReason.UPSTREAM_BLOCK), 1, 0, receivedBytes, 0,
                0, 0);
    }

    @Override
    public Action oversizeAction() {
        return policy.oversizeAction();
    }

    @Override
    public void recordStreamError() {
        if (metrics != null) {
            metrics.recordStreamError("stream");
        }
    }

    @Override
    public void recordDuration(Phase phase, Duration duration) {
        if (metrics != null) {
            metrics.recordContinuationDuration(metricPhase(phase), duration);
        }
    }

    @Override
    public void recordScanIncomplete(Phase phase, Action action) {
        if (metrics != null) {
            metrics.recordContinuationScanIncomplete(metricPhase(phase), action);
        }
    }

    @Override
    public void recordStatus(Status status) {
        if (metrics != null) {
            metrics.recordContinuationStatus(HamzaMetrics.ContinuationStatus.valueOf(status.name()));
        }
    }

    @Override
    public void recordStandard(NormalizedTurn turn, List<DetectorRunEvidence> detectorRuns) {
        records.append(TurnRecord.standard(turn, detectorRuns));
        if (metrics != null) {
            metrics.recordTurn(turn);
        }
        events.info(RECORD_COMMITTED, Map.of(TURN_ID, turn.turnId(),
                PROVIDER, turn.provider(), ACTION, turn.action(), COUNT, turn.findings().size()));
        if (turn.action() == Action.BLOCK) {
            events.info(EGRESS_BLOCKED, Map.of(TURN_ID, turn.turnId(),
                    PROVIDER, turn.provider()));
        } else {
            events.info(EGRESS_RELEASED, Map.of(TURN_ID, turn.turnId(),
                    PROVIDER, turn.provider()));
        }
    }

    @Override
    public void recordBlocked(NormalizedTurn turn, List<DetectorRunEvidence> detectorRuns,
                              List<String> blockingRules) {
        recordStandard(turn, detectorRuns);
        if (metrics != null && blockingRules != null) {
            blockingRules.forEach(metrics::recordEgressBlocked);
        }
    }

    @Override
    public void recordSource(NormalizedTurn turn, ContinuationEvidence evidence,
                             List<DetectorRunEvidence> detectorRuns, long withheldBytes) {
        records.append(new TurnRecord(turn, evidence, detectorRuns));
        if (metrics != null) {
            metrics.recordTurn(turn);
            if (turn.action() == Action.BLOCK) {
                metrics.recordEgressBlocked("exact-data-match");
            }
            metrics.recordContinuationTurn(HamzaMetrics.ContinuationTurnKind.SOURCE,
                    turn.action());
            metrics.recordContinuationStatus(HamzaMetrics.ContinuationStatus.ATTEMPTED);
            metrics.recordContinuationBytes(HamzaMetrics.ContinuationByteKind.WITHHELD,
                    withheldBytes);
        }
        events.info(RECORD_COMMITTED, Map.of(TURN_ID, turn.turnId(),
                PROVIDER, turn.provider(), ACTION, turn.action(), COUNT, turn.findings().size()));
        if (turn.action() == Action.BLOCK) {
            events.info(EGRESS_BLOCKED, Map.of(TURN_ID, turn.turnId(), PROVIDER, turn.provider()));
        }
    }

    @Override
    public void recordDerived(NormalizedTurn turn, ContinuationEvidence evidence,
                              List<DetectorRunEvidence> detectorRuns) {
        records.append(new TurnRecord(turn, evidence, detectorRuns));
        if (metrics != null) {
            metrics.recordTurn(turn);
            metrics.recordContinuationTurn(HamzaMetrics.ContinuationTurnKind.DERIVED, Action.FLAG);
            metrics.recordContinuationStatus(HamzaMetrics.ContinuationStatus.DELIVERED);
            metrics.recordContinuationBytes(HamzaMetrics.ContinuationByteKind.INSPECTED,
                    turn.requestBytesInspected() == null ? 0L : turn.requestBytesInspected());
            metrics.recordContinuationBytes(HamzaMetrics.ContinuationByteKind.EGRESSED,
                    turn.requestBytesEgressed() == null ? 0L : turn.requestBytesEgressed());
        }
        events.info(RECORD_COMMITTED, Map.of(TURN_ID, turn.turnId(),
                PROVIDER, turn.provider(), ACTION, turn.action(), COUNT, turn.findings().size()));
        events.info(EGRESS_RELEASED, Map.of(TURN_ID, turn.turnId(), PROVIDER, turn.provider()));
    }

    private static PolicyResult observed(PolicyResult result) {
        result.detectorEvidence().forEach(run -> events.info(
                run.status() == ai.hamza.policy.DetectionStatus.COMPLETE
                        ? DETECTOR_COMPLETED : DETECTOR_GAP,
                run.reason().isPresent()
                        ? Map.of(DETECTOR, run.detectorId(), STATUS, run.status(),
                                REASON, run.reason().orElseThrow(), COUNT, run.findingCount(),
                                DURATION_MICROS, run.durationMicros())
                        : Map.of(DETECTOR, run.detectorId(), STATUS, run.status(),
                                COUNT, run.findingCount(), DURATION_MICROS, run.durationMicros())));
        if (result.isMask()) {
            events.info(MASK_PLANNED, Map.of(COUNT, result.findings().size(), ACTION, Action.MASK));
        }
        return result;
    }

    private static HamzaMetrics.ContinuationPhase metricPhase(Phase phase) {
        return HamzaMetrics.ContinuationPhase.valueOf(phase.name());
    }
}
