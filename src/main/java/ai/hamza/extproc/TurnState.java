package ai.hamza.extproc;

import ai.hamza.adapter.ProviderAdapter;
import ai.hamza.adapter.RequestView;
import ai.hamza.adapter.TurnDraft;
import ai.hamza.continuation.ManagedMetadataDecision;
import ai.hamza.continuation.QuarantineReservation;
import ai.hamza.edm.EdmTurnAccumulator;
import ai.hamza.policy.Action;
import ai.hamza.policy.Finding;
import ai.hamza.policy.DetectorRunEvidence;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

/**
 * Per-stream state for one Turn (one ext_proc stream == one HTTP exchange). Mutable
 * and confined to a single stream's callbacks, so no synchronisation is needed.
 *
 * <p>The accumulated response body is transient working state, parsed at end-of-stream
 * and then discarded — it never reaches the durable Record (content-free invariant).
 */
final class TurnState implements AutoCloseable {

    static final int MAX_RESPONSE_BYTES = 1024 * 1024;

    static final String OVERSIZE_RULE = "oversize";
    static final String PARTIAL_EGRESS_RULE = "partial-egress";
    static final String WIRE_DRIFT_RULE = "wire-drift";
    static final String OPAQUE_CONTENT_RULE = "opaque-content";
    static final String EVASION_RULE = "evasion-suspected";
    static final String MANAGED_METADATA_RULE = "managed-metadata";
    static final String MANAGED_QUARANTINE_RULE = "managed-quarantine";
    static final String SCAN_INCOMPLETE_RULE = "scan-incomplete";
    static final String CONTINUATION_FAILED_RULE = "continuation-failed";
    static final String CONTINUATION_INELIGIBLE_RULE = "continuation-ineligible";
    static final String RECORD_COMMIT_RULE = "record-commit-failed";

    private final String turnId = UUID.randomUUID().toString();
    private String derivedTurnId;
    private final long startNanos = System.nanoTime();
    private final BoundedResponseBuffer responseBody =
            new BoundedResponseBuffer(MAX_RESPONSE_BYTES);

    private ProviderAdapter adapter;
    private String agent = "unknown";
    private String requestId;
    private String sessionId;
    private String path;
    private String contentEncoding;
    private Long requestContentLength;
    private RequestView request = RequestView.empty();
    private int httpStatus;
    private boolean finalized;
    private boolean oversize;
    private boolean streamedOversize;
    private byte[] streamOverlapTail = new byte[0];
    private long streamedBodyBytes;
    private final LinkedHashMap<String, Finding> streamFindings = new LinkedHashMap<>();
    private EdmTurnAccumulator edmAccumulator;
    private List<Finding> findings = List.of();
    private final LinkedHashMap<String, Integer> edmDistinctCounts = new LinkedHashMap<>();
    private Action action = Action.FLAG;
    private final LinkedHashMap<String, DetectorRunEvidence> detectorRuns = new LinkedHashMap<>();
    private ManagedMetadataDecision.Verified managedMetadata;
    private QuarantineReservation quarantineReservation;
    private long quarantineStartedNanos;

    String turnId() {
        return turnId;
    }

    String recordTurnId() {
        return derivedTurnId == null ? turnId : derivedTurnId;
    }

    String sourceTurnId() {
        return turnId;
    }

    void beginManaged(ManagedMetadataDecision.Verified metadata,
                      QuarantineReservation reservation) {
        this.managedMetadata = java.util.Objects.requireNonNull(metadata, "metadata");
        this.quarantineReservation = java.util.Objects.requireNonNull(reservation, "reservation");
        this.quarantineStartedNanos = System.nanoTime();
    }

    void beginManagedPassThrough(ManagedMetadataDecision.Verified metadata) {
        this.managedMetadata = java.util.Objects.requireNonNull(metadata, "metadata");
        promoteToManagedPassThrough();
    }

    boolean isManaged() {
        return managedMetadata != null;
    }

    ManagedMetadataDecision.Verified managedMetadata() {
        return managedMetadata;
    }

    boolean acceptManagedBody(long actualBytes) {
        return quarantineReservation != null
                && quarantineReservation.acceptActual(
                new ai.hamza.continuation.ByteCount(actualBytes));
    }

    java.time.Duration quarantineDuration() {
        return quarantineStartedNanos == 0 ? java.time.Duration.ZERO
                : java.time.Duration.ofNanos(System.nanoTime() - quarantineStartedNanos);
    }

    void releaseQuarantine() {
        if (quarantineReservation != null) {
            quarantineReservation.close();
            quarantineReservation = null;
        }
    }

    void promoteToDerived() {
        if (!isManaged() || derivedTurnId != null) {
            throw new IllegalStateException("invalid managed Turn promotion");
        }
        derivedTurnId = UUID.randomUUID().toString();
        edmDistinctCounts.clear();
        detectorRuns.clear();
        findings = List.of();
        action = Action.FLAG;
    }

    void promoteToManagedPassThrough() {
        if (!isManaged() || derivedTurnId != null) {
            throw new IllegalStateException("invalid managed pass-through promotion");
        }
        managedMetadata = null;
    }

    boolean isDerived() {
        return derivedTurnId != null;
    }

    ProviderAdapter adapter() {
        return adapter;
    }

    void selectAdapter(ProviderAdapter adapter) {
        this.adapter = adapter;
    }

    void setAgent(String agent) {
        if (agent != null && !agent.isBlank()) {
            this.agent = agent;
        }
    }

    String agent() {
        return agent;
    }

    void setRequestId(String requestId) {
        if (requestId != null && !requestId.isBlank()) {
            this.requestId = requestId;
        }
    }

    String requestId() {
        return requestId;
    }

    void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    void setPath(String path) {
        this.path = path;
    }

    String path() {
        return path;
    }

    void setContentEncoding(String contentEncoding) {
        this.contentEncoding = contentEncoding;
    }

    String contentEncoding() {
        return contentEncoding;
    }

    void setRequestContentLength(long contentLength) {
        if (contentLength >= 0) {
            this.requestContentLength = contentLength;
        }
    }

    Long requestContentLength() {
        return requestContentLength;
    }

    void setRequest(RequestView request) {
        if (request != null) {
            this.request = request;
        }
    }

    void setHttpStatus(int httpStatus) {
        this.httpStatus = httpStatus;
    }

    void setPolicy(List<Finding> findings, Action action) {
        this.findings = findings == null ? List.of() : List.copyOf(findings);
        this.action = action == null ? Action.FLAG : action;
        if (oversize) {
            addOversizeFinding(this.action == Action.BLOCK ? Action.BLOCK : Action.FLAG);
        }
    }

    void mergeDetectorEvidence(List<DetectorRunEvidence> runs) {
        if (runs == null) {
            return;
        }
        for (DetectorRunEvidence run : runs) {
            detectorRuns.merge(run.detectorId(), run, TurnState::mergeEvidence);
        }
    }

    List<DetectorRunEvidence> detectorEvidence() {
        return List.copyOf(detectorRuns.values());
    }

    private static DetectorRunEvidence mergeEvidence(DetectorRunEvidence left,
                                                      DetectorRunEvidence right) {
        ai.hamza.policy.DetectionStatus status = severity(right.status()) > severity(left.status())
                ? right.status() : left.status();
        java.util.Optional<ai.hamza.policy.DetectionReason> reason =
                status == ai.hamza.policy.DetectionStatus.COMPLETE
                        ? java.util.Optional.empty()
                        : (right.reason().isPresent() ? right.reason() : left.reason());
        return new DetectorRunEvidence(left.detectorId(), left.detectorVersion(), status, reason,
                left.receivedSegments() + right.receivedSegments(),
                left.inspectedSegments() + right.inspectedSegments(),
                left.receivedBytes() + right.receivedBytes(),
                left.inspectedBytes() + right.inspectedBytes(),
                left.durationMicros() + right.durationMicros(),
                left.findingCount() + right.findingCount());
    }

    private static int severity(ai.hamza.policy.DetectionStatus status) {
        return switch (status) {
            case COMPLETE -> 0;
            case SKIPPED -> 1;
            case UNAVAILABLE -> 2;
            case INCOMPLETE -> 3;
        };
    }

    void mergeEdmCounts(java.util.Map<String, Integer> counts) {
        if (counts == null) {
            return;
        }
        counts.forEach((registry, count) -> {
            if (registry != null && !registry.isBlank() && count != null) {
                edmDistinctCounts.merge(registry, count, Math::max);
            }
        });
    }

    java.util.Map<String, Integer> edmDistinctCounts() {
        return java.util.Map.copyOf(edmDistinctCounts);
    }

    List<Finding> findings() {
        return findings;
    }

    Action action() {
        return action;
    }

    void markOversize() {
        markOversize(Action.FLAG);
    }

    void markOversize(Action action) {
        oversize = true;
        Action resolved = action == Action.BLOCK ? Action.BLOCK : Action.FLAG;
        if (resolved == Action.BLOCK) {
            this.action = Action.BLOCK;
        }
        addOversizeFinding(resolved);
    }

    boolean isOversize() {
        return oversize;
    }

    void markStreamedOversize() {
        streamedOversize = true;
    }

    boolean isStreamedOversize() {
        return streamedOversize;
    }

    /**
     * Append a streamed request-body chunk and return the window to scan: the previous
     * chunk's tail (up to {@code overlapBytes}) prepended to this chunk, so a secret
     * spanning a chunk boundary still matches. Keeps only the overlap tail — the full
     * streamed body is never accumulated (bounded memory regardless of body size).
     */
    byte[] nextStreamScanWindow(byte[] chunk, int overlapBytes) {
        byte[] safeChunk = chunk == null ? new byte[0] : chunk;
        byte[] window = new byte[streamOverlapTail.length + safeChunk.length];
        System.arraycopy(streamOverlapTail, 0, window, 0, streamOverlapTail.length);
        System.arraycopy(safeChunk, 0, window, streamOverlapTail.length, safeChunk.length);
        streamedBodyBytes += safeChunk.length;
        int keep = Math.min(overlapBytes, window.length);
        streamOverlapTail = Arrays.copyOfRange(window, window.length - keep, window.length);
        return window;
    }

    /**
     * Accumulate Findings across streamed chunks, deduplicated by rule. A later chunk
     * may upgrade a rule's Action (e.g. an EDM registry crossing its block threshold
     * mid-Turn), so the most severe Action per rule wins.
     */
    void accumulateStreamFindings(List<Finding> found) {
        for (Finding f : found) {
            streamFindings.merge(f.rule(), f,
                    (existing, incoming) -> severity(incoming.action()) > severity(existing.action())
                            ? incoming : existing);
        }
    }

    private static int severity(Action a) {
        return switch (a) {
            case FLAG -> 0;
            case MASK -> 1;
            case BLOCK -> 2;
        };
    }

    /** Per-Turn EDM accumulation across streamed chunks (threshold per Turn). */
    EdmTurnAccumulator edmAccumulator() {
        if (edmAccumulator == null) {
            edmAccumulator = new EdmTurnAccumulator();
        }
        return edmAccumulator;
    }

    List<Finding> streamFindings() {
        return List.copyOf(streamFindings.values());
    }

    long streamedBodyBytes() {
        return streamedBodyBytes;
    }

    private Long requestBytesReceived;
    private Long requestBytesInspected;
    private Long requestBytesEgressed;

    void setRequestByteCounts(Long received, Long inspected, Long egressed) {
        this.requestBytesReceived = nonNegativeOrNull(received);
        this.requestBytesInspected = nonNegativeOrNull(inspected);
        this.requestBytesEgressed = nonNegativeOrNull(egressed);
    }

    void setRequestBytesEgressed(Long egressed) {
        this.requestBytesEgressed = nonNegativeOrNull(egressed);
    }

    Long requestBytesReceived() {
        return requestBytesReceived;
    }

    Long requestBytesInspected() {
        return requestBytesInspected;
    }

    Long requestBytesEgressed() {
        return requestBytesEgressed;
    }

    String sessionId() {
        return sessionId;
    }

    RequestView request() {
        return request;
    }

    void appendResponseBody(byte[] chunk) {
        responseBody.append(chunk);
    }

    int retainedResponseBytes() {
        return responseBody.retainedBytes();
    }

    boolean responseTruncated() {
        return responseBody.truncated();
    }

    boolean markFinalizedOnce() {
        if (finalized) {
            return false;
        }
        finalized = true;
        return true;
    }

    boolean isFinalized() {
        return finalized;
    }

    long elapsedMs() {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    TurnDraft toDraft() {
        return new TurnDraft(recordTurnId(), requestId, sessionId, agent, request, httpStatus,
                responseBody.snapshot(), elapsedMs(), requestBytesReceived,
                requestBytesInspected, requestBytesEgressed, edmDistinctCounts());
    }

    @Override
    public void close() {
        responseBody.close();
        releaseQuarantine();
    }

    private static Long nonNegativeOrNull(Long value) {
        return value == null || value < 0 ? null : value;
    }

    private void addOversizeFinding(Action action) {
        ArrayList<Finding> marked = new ArrayList<>(findings);
        boolean replaced = false;
        for (int i = 0; i < marked.size(); i++) {
            if (marked.get(i).rule().equals(OVERSIZE_RULE)) {
                marked.set(i, new Finding(OVERSIZE_RULE, action));
                replaced = true;
            }
        }
        if (!replaced) {
            marked.add(new Finding(OVERSIZE_RULE, action));
        }
        findings = List.copyOf(marked);
    }
}
