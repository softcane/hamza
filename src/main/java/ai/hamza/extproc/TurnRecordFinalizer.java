package ai.hamza.extproc;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.adapter.ProviderAdapter;
import ai.hamza.persistence.ContinuationEvidence;
import ai.hamza.policy.Action;
import ai.hamza.policy.PolicyResult;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static ai.hamza.extproc.StructuredEventLogger.Event.EGRESS_BLOCKED;
import static ai.hamza.extproc.StructuredEventLogger.Event.RECORD_COMMITTED;
import static ai.hamza.extproc.StructuredEventLogger.Event.RECORD_FAILED;
import static ai.hamza.extproc.StructuredEventLogger.Field.ACTION;
import static ai.hamza.extproc.StructuredEventLogger.Field.COUNT;
import static ai.hamza.extproc.StructuredEventLogger.Field.PROVIDER;
import static ai.hamza.extproc.StructuredEventLogger.Field.REASON;
import static ai.hamza.extproc.StructuredEventLogger.Field.STATUS;
import static ai.hamza.extproc.StructuredEventLogger.Field.TURN_ID;

/**
 * Record finalization for one Turn: commits the durable Record exactly once (standard,
 * blocked, or derived) and emits the immediate transport Block response. Shared by the
 * session and by every route's block path so the finalize-once guard and Coach-session
 * bookkeeping live in a single place.
 */
final class TurnRecordFinalizer {

    private static final StructuredEventLogger events =
            StructuredEventLogger.forClass(TurnRecordFinalizer.class);

    private final TurnPipeline pipeline;
    private final boolean coachEnabled;
    private final CoachSessionTracker coachSessions;

    TurnRecordFinalizer(TurnPipeline pipeline, boolean coachEnabled,
                        CoachSessionTracker coachSessions) {
        this.pipeline = pipeline;
        this.coachEnabled = coachEnabled;
        this.coachSessions = coachSessions;
    }

    void finalizeTurn(TurnState state) {
        ProviderAdapter adapter = state.adapter();
        if (state.isManaged() && !state.isDerived()) {
            return;
        }
        if (adapter == null || !state.markFinalizedOnce()) {
            if (adapter == null) {
                state.close();
            }
            return; // unknown Provider, or already recorded (e.g. blocked)
        }
        try {
            NormalizedTurn turn = adapter.finalizeTurn(state.toDraft())
                    .withPolicy(state.findings(), state.action());
            if (state.responseTruncated()) {
                turn = turn.withStatus("response-truncated");
            }
            if (state.isManaged()) {
                pipeline.recordDerived(turn, ContinuationEvidence.derived(
                                state.managedMetadata().recoveryId().value(), state.sourceTurnId()),
                        state.detectorEvidence());
            } else {
                pipeline.recordStandard(turn, state.detectorEvidence());
            }
            events.info(RECORD_COMMITTED, Map.of(TURN_ID, turn.turnId(),
                    PROVIDER, turn.provider(), STATUS, turn.status(), ACTION, turn.action(),
                    COUNT, turn.findings().size()));
        } catch (Exception e) {
            events.warn(RECORD_FAILED, Map.of(TURN_ID, state.turnId(),
                    REASON, e.getClass().getSimpleName()));
        } finally {
            state.close();
        }
    }

    void recordBlockedTurn(TurnState state, PolicyResult policy) {
        if (!state.markFinalizedOnce()) {
            return;
        }
        String provider = state.adapter() != null ? state.adapter().provider() : "unknown";
        String model = state.request() != null ? state.request().requestedModel() : null;
        NormalizedTurn turn = NormalizedTurn.blocked(state.turnId(), state.requestId(),
                state.sessionId(), state.agent(), provider, model, policy.findings(),
                state.elapsedMs(), state.requestBytesReceived(), state.requestBytesInspected(),
                state.requestBytesEgressed(), state.edmDistinctCounts());
        try {
            pipeline.recordBlocked(turn, state.detectorEvidence(), policy.blockingRules());
            events.info(EGRESS_BLOCKED, Map.of(TURN_ID, turn.turnId(), PROVIDER, provider,
                    COUNT, policy.blockingRules().size()));
        } catch (Exception e) {
            events.warn(RECORD_FAILED, Map.of(TURN_ID, state.turnId(),
                    REASON, e.getClass().getSimpleName()));
        }
    }

    TurnPipeline.Decision blockOversizeTurn(TurnState state, List<String> blockingRules) {
        List<String> rules = blockingRules == null || blockingRules.isEmpty()
                ? List.of(TurnState.OVERSIZE_RULE) : blockingRules;
        PolicyResult policy = new PolicyResult(state.findings(), Action.BLOCK, Optional.empty(), rules);
        recordBlockedTurn(state, policy);
        return emitBlock(state, rules);
    }

    /**
     * Emit the immediate Block response. Coach only shapes the 403 body; the
     * Block decision, its Findings, and the recorded Turn are already finalized above and
     * are identical whether Coach is on or off.
     */
    TurnPipeline.Decision emitBlock(TurnState state, List<String> blockingRules) {
        String provider = state.adapter() != null ? state.adapter().provider() : null;
        // Once a session has been shown a coach, remember it so a later re-encoded retry in
        // the same session escalates (R3.3). Only meaningful when Coach is enabled.
        if (coachEnabled) {
            coachSessions.markCoached(state.sessionId());
        }
        return new TurnPipeline.Block(provider, blockingRules);
    }
}
