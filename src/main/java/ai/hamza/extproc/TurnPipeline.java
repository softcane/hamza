package ai.hamza.extproc;

import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.edm.EdmTurnAccumulator;
import ai.hamza.persistence.ContinuationEvidence;
import ai.hamza.policy.Action;
import ai.hamza.policy.DetectorRunEvidence;
import ai.hamza.policy.PolicyResult;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Plain-Java boundary between gRPC transport and Turn processing. It deliberately
 * contains no Envoy, gRPC, repository, detector implementation, or metrics types.
 */
public interface TurnPipeline {

    enum BodyMode { UNCHANGED, NONE, BUFFERED, BUFFERED_PARTIAL, STREAMED }

    record RequestHeaders(Map<String, String> routingHeaders,
                          Map<String, List<String>> managedHeaders,
                          Set<String> duplicateRoutingHeaders,
                          String routeProvider,
                          boolean endOfStream) {
        public RequestHeaders {
            routingHeaders = routingHeaders == null ? Map.of() : Map.copyOf(routingHeaders);
            if (managedHeaders == null) {
                managedHeaders = Map.of();
            } else {
                java.util.LinkedHashMap<String, List<String>> copied = new java.util.LinkedHashMap<>();
                managedHeaders.forEach((key, values) -> copied.put(key, List.copyOf(values)));
                managedHeaders = Map.copyOf(copied);
            }
            duplicateRoutingHeaders = duplicateRoutingHeaders == null
                    ? Set.of() : Set.copyOf(duplicateRoutingHeaders);
        }

        boolean duplicated(String name) {
            return duplicateRoutingHeaders.contains(name);
        }
    }

    sealed interface Decision permits Continue, Block { }

    record Continue(BodyMode bodyMode, Set<String> removeHeaders,
                    byte[] replacementBody, boolean repairManagedFraming)
            implements Decision {
        public Continue {
            bodyMode = bodyMode == null ? BodyMode.UNCHANGED : bodyMode;
            removeHeaders = removeHeaders == null ? Set.of() : Set.copyOf(removeHeaders);
            replacementBody = replacementBody == null ? null : replacementBody.clone();
        }

        @Override
        public byte[] replacementBody() {
            return replacementBody == null ? null : replacementBody.clone();
        }

        static Continue unchanged() {
            return new Continue(BodyMode.UNCHANGED, Set.of(), null, false);
        }

        static Continue mode(BodyMode mode) {
            return new Continue(mode, Set.of(), null, false);
        }

        static Continue mode(BodyMode mode, Set<String> removeHeaders) {
            return new Continue(mode, removeHeaders, null, false);
        }

        static Continue replace(byte[] body, boolean repairManagedFraming) {
            return new Continue(BodyMode.UNCHANGED, Set.of(), body, repairManagedFraming);
        }
    }

    record Block(String provider, List<String> blockingRules) implements Decision {
        public Block {
            blockingRules = blockingRules == null ? List.of() : List.copyOf(blockingRules);
        }
    }

    interface Session extends AutoCloseable {
        Decision onRequestHeaders(RequestHeaders headers);

        Decision onRequestBody(byte[] body, boolean endOfStream);

        void onResponseHeaders(int status, boolean endOfStream);

        void onResponseBody(byte[] body, boolean endOfStream);

        void onTransportError(Throwable failure);

        void onTransportCompleted();

        @Override
        void close();
    }

    Session openSession(boolean coachEnabled);

    enum Phase { QUARANTINE, SOURCE_SCAN, FINAL_SCAN }

    enum Status { ATTEMPTED, ELIGIBLE, DELIVERED, REJECTED, FAILED_CLOSED }

    PolicyResult inspect(byte[] body);

    PolicyResult inspectPrefix(byte[] body);

    PolicyResult inspectStream(byte[] window, EdmTurnAccumulator accumulator);

    List<DetectorRunEvidence> upstreamBlockEvidence(long receivedBytes);

    Action oversizeAction();

    void recordStreamError();

    void recordDuration(Phase phase, Duration duration);

    void recordScanIncomplete(Phase phase, Action action);

    void recordStatus(Status status);

    void recordStandard(NormalizedTurn turn, List<DetectorRunEvidence> detectorRuns);

    void recordBlocked(NormalizedTurn turn, List<DetectorRunEvidence> detectorRuns,
                       List<String> blockingRules);

    void recordSource(NormalizedTurn turn, ContinuationEvidence evidence,
                      List<DetectorRunEvidence> detectorRuns, long withheldBytes);

    void recordDerived(NormalizedTurn turn, ContinuationEvidence evidence,
                       List<DetectorRunEvidence> detectorRuns);
}
