package ai.hamza.attest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Canonical, content-free hashing for the tamper-evident Record chain.
 * Every hashed field is already accounting metadata — rule ids, Actions,
 * token counts, timestamps, config fingerprints — <strong>never</strong> a raw prompt,
 * code, or secret value (content-free invariant). The same routine runs on the write path
 * ({@code TurnRepository}) and the verify path ({@code ChainVerifier}), so an
 * independent walk of the DB recomputes byte-identical hashes.
 */
public final class RecordHasher {

    /** Chain root: the {@code prev_hash} of the very first entry. */
    public static final String GENESIS = "0".repeat(64);
    public static final String LEGACY_RECORD_VERSION = "hamza-record/v2";
    public static final String REQUEST_ID_RECORD_VERSION = "hamza-record/v3";
    public static final String CONTINUATION_RECORD_VERSION = "hamza-record/v4";
    public static final String CURRENT_RECORD_VERSION = "hamza-record/v5";
    public static final String CURRENT_RECOVERY_OUTCOME_VERSION = "hamza-recovery-outcome/v1";

    /** Field separator (ASCII unit separator) — escaped out of field values by {@link #n}. */
    private static final char FS = '\u001f';
    /** Finding separator (ASCII record separator). */
    private static final char RS = '\u001e';
    /** rule/action separator within one Finding (ASCII group separator). */
    private static final char GS = '\u001d';
    /** Sentinel for a null field, so null and "" hash differently. */
    private static final String NULL = "\u0000null";

    private RecordHasher() {
    }

    /**
     * The tamper-evident hash of one Record entry: SHA-256 over the previous entry's
     * hash plus this entry's content-free fields. V4 covers accounting, continuation
     * evidence, EDM events, and Findings. Chaining the
     * previous hash in is what makes an edit to any earlier row cascade-detectable.
     */
    public static String entryHash(String prevHash, HashableTurn t) {
        String version = t.hashVersion() == null ? LEGACY_RECORD_VERSION : t.hashVersion();
        if (!isSupportedRecordVersion(version)) {
            throw new IllegalArgumentException("unsupported Record hash version");
        }
        StringBuilder sb = new StringBuilder(256);
        sb.append(version).append(FS)
                .append(prevHash).append(FS)
                .append(n(t.turnId())).append(FS);
        if (!LEGACY_RECORD_VERSION.equals(version)) {
            sb.append(n(t.requestId())).append(FS);
        }
        sb.append(n(t.sessionId())).append(FS)
                .append(n(t.agent())).append(FS)
                .append(n(t.provider())).append(FS)
                .append(n(t.requestedModel())).append(FS)
                .append(n(t.servedModel())).append(FS)
                .append(n(t.status())).append(FS)
                .append(t.inputTokens()).append(FS)
                .append(t.cachedInputTokens()).append(FS)
                .append(t.uncachedInputTokens()).append(FS)
                .append(t.outputTokens()).append(FS)
                .append(t.reasoningTokens()).append(FS)
                .append(t.totalTokens()).append(FS)
                .append(t.toolCalls()).append(FS)
                .append(n(t.action())).append(FS)
                .append(t.durationMs()).append(FS)
                .append(n(t.ts())).append(FS)
                .append(n(t.posture())).append(FS)
                .append(n(t.configFingerprint())).append(FS);
        if (CONTINUATION_RECORD_VERSION.equals(version) || CURRENT_RECORD_VERSION.equals(version)) {
            sb.append("request-bytes").append(FS)
                    .append(n(t.requestBytesReceived())).append(FS)
                    .append(n(t.requestBytesInspected())).append(FS)
                    .append(n(t.requestBytesEgressed())).append(FS);
            ContinuationHashFields c = t.continuation();
            sb.append("continuation").append(FS)
                    .append(n(c.role())).append(FS)
                    .append(n(c.recoveryId())).append(FS)
                    .append(n(c.parentTurnId())).append(FS)
                    .append(n(c.recipeId())).append(FS)
                    .append(n(c.recipeVersion())).append(FS)
                    .append(n(c.workflowProfileId())).append(FS)
                    .append(n(c.workflowProfileVersion())).append(FS)
                    .append(n(c.continuationStatus())).append(FS)
                    .append(n(c.reasonCode())).append(FS)
                    .append(n(c.taskPath())).append(FS)
                    .append(n(c.taskStatus())).append(FS)
                    .append(n(c.requestBytesWithheld())).append(FS);
            if (CURRENT_RECORD_VERSION.equals(version)) {
                sb.append(n(c.maskedValueCount())).append(FS);
            }
            sb.append("edm-events").append(FS);
            List<String> events = new ArrayList<>(t.edmEventKeys());
            events.sort(null);
            for (String event : events) {
                sb.append(event).append(RS);
            }
            if (CURRENT_RECORD_VERSION.equals(version)) {
                sb.append(FS).append("detector-runs").append(FS);
                List<String> runs = new ArrayList<>(t.detectorRunKeys());
                runs.sort(null);
                for (String run : runs) {
                    sb.append(run).append(RS);
                }
            }
            sb.append(FS).append("findings").append(FS);
        }
        // Findings are sorted (rule, action) so ordering in the child table cannot
        // change the hash; only the SET of Findings does.
        List<String> keys = new ArrayList<>(t.findingKeys());
        keys.sort(null);
        for (String k : keys) {
            sb.append(k).append(RS);
        }
        return sha256Hex(sb.toString());
    }

    public static boolean isSupportedRecordVersion(String version) {
        return LEGACY_RECORD_VERSION.equals(version)
                || REQUEST_ID_RECORD_VERSION.equals(version)
                || CONTINUATION_RECORD_VERSION.equals(version)
                || CURRENT_RECORD_VERSION.equals(version);
    }

    /** Hash-chain entry for one signed, content-free Recovery Outcome. */
    public static String recoveryOutcomeEntryHash(String prevHash, RecoveryOutcomeHashFields outcome) {
        StringBuilder sb = new StringBuilder(256);
        sb.append(CURRENT_RECOVERY_OUTCOME_VERSION).append(FS)
                .append(n(prevHash)).append(FS)
                .append(n(outcome.recoveryId())).append(FS)
                .append(n(outcome.status())).append(FS)
                .append(n(outcome.agent())).append(FS)
                .append(n(outcome.agentVersion())).append(FS)
                .append(n(outcome.workflowProfileId())).append(FS)
                .append(outcome.workflowProfileVersion()).append(FS)
                .append(n(outcome.acceptanceGateId())).append(FS)
                .append(n(outcome.startedAt())).append(FS)
                .append(n(outcome.completedAt())).append(FS)
                .append(n(outcome.signatureVersion())).append(FS)
                .append(n(outcome.signature())).append(FS);
        return sha256Hex(sb.toString());
    }

    /**
     * A stable, content-free fingerprint of the effective policy config the Gate ran
     * under. Two Gates with the same posture/rules/thresholds produce the same
     * fingerprint; any config change shifts it, so the report can show config drift
     * across a window without ever storing the config values themselves.
     */
    public static String configFingerprint(String posture, Map<String, String> ruleActions,
                                           int maxBodyBytes, boolean streamOversize,
                                           List<String> controlPlanePaths, int edmBlockThreshold,
                                           boolean edmEnabled) {
        StringBuilder sb = new StringBuilder(128);
        sb.append("hamza-config/v2").append(FS)
                .append(n(posture)).append(FS)
                .append(maxBodyBytes).append(FS)
                .append(streamOversize).append(FS)
                .append(edmBlockThreshold).append(FS)
                .append(edmEnabled).append(FS);
        // Sort both the map and the list for a deterministic fingerprint.
        Map<String, String> sortedRules = new TreeMap<>(
                ruleActions == null ? Map.of() : ruleActions);
        for (Map.Entry<String, String> e : sortedRules.entrySet()) {
            sb.append(n(e.getKey())).append(GS).append(n(e.getValue())).append(RS);
        }
        sb.append(FS);
        List<String> paths = new ArrayList<>(
                controlPlanePaths == null ? List.of() : controlPlanePaths);
        paths.sort(null);
        for (String p : paths) {
            sb.append(n(p)).append(RS);
        }
        return sha256Hex(sb.toString());
    }

    public static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Null-safe canonical form of one field. Separators and the null-sentinel prefix are
     * escaped: some hashed fields (e.g. {@code requestedModel}) come from client JSON and
     * may legally contain FS/RS/GS, and unescaped they would let two different field
     * tuples concatenate to identical bytes — an undetectable edit in the exact layer
     * that exists to detect edits. Canon bump: v1 → v2.
     */
    private static String n(String s) {
        if (s == null) {
            return NULL;
        }
        return s.replace("\\", "\\\\")
                .replace("\u0000", "\\0")
                .replace(String.valueOf(FS), "\\u")
                .replace(String.valueOf(RS), "\\r")
                .replace(String.valueOf(GS), "\\g");
    }

    private static String n(Number value) {
        return value == null ? NULL : value.toString();
    }

    /**
     * The canonical, order-insensitive key for one Finding used inside the entry hash:
     * {@code rule<GS>action}. Callers on the write and verify paths must build finding
     * keys through this method so the separator lives in exactly one place.
     */
    public static String findingKey(String rule, String action) {
        return n(rule) + GS + n(action);
    }

    /** Canonical detector-qualified Finding key used by {@code hamza-record/v5}. */
    public static String findingKey(String detector, String rule, String action) {
        return n(detector) + GS + n(rule) + GS + n(action);
    }

    /** Canonical content-free key for one durable detector run. */
    public static String detectorRunKey(String detector, String version, String status,
                                        String reason, int receivedSegments,
                                        int inspectedSegments, long receivedBytes,
                                        long inspectedBytes, long durationMicros,
                                        int findingCount) {
        return n(detector) + GS + n(version) + GS + n(status) + GS + n(reason) + GS
                + receivedSegments + GS + inspectedSegments + GS + receivedBytes + GS
                + inspectedBytes + GS + durationMicros + GS + findingCount;
    }

    /** Canonical, order-insensitive key for one content-free EDM accounting event. */
    public static String edmEventKey(String registry, int distinctCount, String action) {
        return n(registry) + GS + distinctCount + GS + n(action);
    }

    /** Content-free Safe Continuation fields covered by {@code hamza-record/v4}. */
    public record ContinuationHashFields(
            String role, String recoveryId, String parentTurnId, String recipeId,
            Integer recipeVersion, String workflowProfileId, Integer workflowProfileVersion,
            String continuationStatus, String reasonCode, String taskPath, String taskStatus,
            Long requestBytesWithheld, Integer maskedValueCount) {

        public ContinuationHashFields(
                String role, String recoveryId, String parentTurnId, String recipeId,
                Integer recipeVersion, String workflowProfileId, Integer workflowProfileVersion,
                String continuationStatus, String reasonCode, String taskPath, String taskStatus,
                Long requestBytesWithheld) {
            this(role, recoveryId, parentTurnId, recipeId, recipeVersion, workflowProfileId,
                    workflowProfileVersion, continuationStatus, reasonCode, taskPath, taskStatus,
                    requestBytesWithheld, null);
        }

        public static ContinuationHashFields none() {
            return new ContinuationHashFields("STANDARD", null, null, null, null,
                    null, null, null, null, null, null, null, null);
        }

        @Override
        public String toString() {
            return "ContinuationHashFields[role=" + role + "]";
        }
    }

    /** Content-free projection covered by the Recovery Outcome hash chain. */
    public record RecoveryOutcomeHashFields(
            String recoveryId, String status, String agent, String agentVersion,
            String workflowProfileId, int workflowProfileVersion,
            String acceptanceGateId, String startedAt, String completedAt,
            String signatureVersion, String signature) {

        @Override
        public String toString() {
            return "RecoveryOutcomeHashFields[status=" + status + "]";
        }
    }

    /**
     * The content-free projection of a Record row that the hash covers. Built
     * identically on the write path and the verify path.
     *
     * @param findingKeys one {@code rule<GS>action} string per Finding (order-insensitive)
     */
    public record HashableTurn(
            String hashVersion, String turnId, String requestId, String sessionId, String agent, String provider,
            String requestedModel, String servedModel, String status,
            long inputTokens, long cachedInputTokens, long uncachedInputTokens,
            long outputTokens, long reasoningTokens, long totalTokens,
            int toolCalls, String action, long durationMs, String ts,
            String posture, String configFingerprint,
            Long requestBytesReceived, Long requestBytesInspected, Long requestBytesEgressed,
            ContinuationHashFields continuation, List<String> edmEventKeys,
            List<String> detectorRunKeys,
            List<String> findingKeys) {

        public HashableTurn(
                String hashVersion, String turnId, String requestId, String sessionId,
                String agent, String provider, String requestedModel, String servedModel,
                String status, long inputTokens, long cachedInputTokens,
                long uncachedInputTokens, long outputTokens, long reasoningTokens,
                long totalTokens, int toolCalls, String action, long durationMs, String ts,
                String posture, String configFingerprint, Long requestBytesReceived,
                Long requestBytesInspected, Long requestBytesEgressed,
                ContinuationHashFields continuation, List<String> edmEventKeys,
                List<String> findingKeys) {
            this(hashVersion, turnId, requestId, sessionId, agent, provider, requestedModel,
                    servedModel, status, inputTokens, cachedInputTokens, uncachedInputTokens,
                    outputTokens, reasoningTokens, totalTokens, toolCalls, action, durationMs,
                    ts, posture, configFingerprint, requestBytesReceived, requestBytesInspected,
                    requestBytesEgressed, continuation, edmEventKeys, List.of(), findingKeys);
        }

        public HashableTurn(String hashVersion, String turnId, String requestId,
                            String sessionId, String agent, String provider,
                            String requestedModel, String servedModel, String status,
                            long inputTokens, long cachedInputTokens, long uncachedInputTokens,
                            long outputTokens, long reasoningTokens, long totalTokens,
                            int toolCalls, String action, long durationMs, String ts,
                            String posture, String configFingerprint, List<String> findingKeys) {
            this(hashVersion, turnId, requestId, sessionId, agent, provider, requestedModel,
                    servedModel, status, inputTokens, cachedInputTokens, uncachedInputTokens,
                    outputTokens, reasoningTokens, totalTokens, toolCalls, action, durationMs,
                    ts, posture, configFingerprint, null, null, null,
                    ContinuationHashFields.none(), List.of(), List.of(), findingKeys);
        }

        public HashableTurn(String turnId, String sessionId, String agent, String provider,
                            String requestedModel, String servedModel, String status,
                            long inputTokens, long cachedInputTokens, long uncachedInputTokens,
                            long outputTokens, long reasoningTokens, long totalTokens,
                            int toolCalls, String action, long durationMs, String ts,
                            String posture, String configFingerprint, List<String> findingKeys) {
            this(CURRENT_RECORD_VERSION, turnId, null, sessionId, agent, provider,
                    requestedModel, servedModel, status, inputTokens, cachedInputTokens,
                    uncachedInputTokens, outputTokens, reasoningTokens, totalTokens, toolCalls,
                    action, durationMs, ts, posture, configFingerprint, null, null, null,
                    ContinuationHashFields.none(), List.of(), List.of(), findingKeys);
        }

        public HashableTurn {
            hashVersion = hashVersion == null ? LEGACY_RECORD_VERSION : hashVersion;
            continuation = continuation == null ? ContinuationHashFields.none() : continuation;
            edmEventKeys = edmEventKeys == null ? List.of() : List.copyOf(edmEventKeys);
            detectorRunKeys = detectorRunKeys == null ? List.of() : List.copyOf(detectorRunKeys);
            findingKeys = findingKeys == null ? List.of() : List.copyOf(findingKeys);
        }
    }
}
