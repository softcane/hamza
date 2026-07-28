package ai.hamza.config;

import ai.hamza.continuation.WorkflowProfile;
import ai.hamza.continuation.WorkflowShape;
import ai.hamza.policy.Action;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * All Hamza tunables ({@code @ConfigurationProperties} for every knob). Sensible
 * defaults for local Compose; override via env vars / config.
 *
 * @param metrics metrics-related tunables
 * @param policy  secret-detection policy (Posture + per-rule Action overrides)
 * @param edm     Exact Data Match fingerprinting
 * @param coach   how a Block presents itself (Coach is Block's
 *                presentation only, never a change to WHAT is blocked)
 */
@ConfigurationProperties(prefix = "hamza")
@Validated
public record HamzaProperties(Metrics metrics, Policy policy, Edm edm, Coach coach,
                              @Valid Continuation continuation) {

    public static final int DEFAULT_MAX_BODY_BYTES = 65_536;
    public static final int DEFAULT_EDM_BLOCK_THRESHOLD = 10;
    public static final int DEFAULT_EDM_MAX_CONTINUATION_ENTRIES = 1_000_000;
    public static final long DEFAULT_CONTINUATION_MAX_BODY_BYTES = 8L * 1024 * 1024;
    /**
     * Managed masking bounds. These admit a real CLI Agent Turn: an Agent harness
     * appends its whole history to every request, so a managed body grows with the
     * session and a 64 KiB bound would Block every real Turn after the first few.
     * They stay well under {@link #DEFAULT_CONTINUATION_MAX_BODY_BYTES} so the
     * quarantine admission bound remains the outer limit.
     */
    public static final int DEFAULT_MASK_MAX_BODY_BYTES = 1_048_576;
    public static final int DEFAULT_MASK_MAX_SEGMENTS = 1_024;
    public static final long DEFAULT_CONTINUATION_TOTAL_MEMORY_BYTES = 64L * 1024 * 1024;
    public static final int DEFAULT_CONTINUATION_CONCURRENCY = 8;
    public static final int DEFAULT_CONTINUATION_CANDIDATE_BUDGET = 50_000;
    public static final int DEFAULT_COACH_STATUS = 403;
    public static final String DEFAULT_COVERED_POPULATION = "Covered: managed Agent traffic routed "
            + "through the Hamza Gate by enforced Provider egress policy. Not covered: laptops off "
            + "the managed network, direct Provider egress that bypasses that policy, browser/IDE-cloud shadow AI.";
    public static final List<String> DEFAULT_CONTROL_PLANE_PATHS = List.of(
            "/backend-api/codex/responses/compact");

    @org.springframework.boot.context.properties.bind.ConstructorBinding
    public HamzaProperties {
        metrics = metrics == null ? new Metrics(Map.of()) : metrics;
        policy = policy == null ? new Policy(Action.FLAG, Map.of(),
                DEFAULT_MAX_BODY_BYTES, DEFAULT_CONTROL_PLANE_PATHS, true) : policy;
        edm = edm == null ? new Edm(null, DEFAULT_EDM_BLOCK_THRESHOLD, true, null,
                DEFAULT_EDM_MAX_CONTINUATION_ENTRIES) : edm;
        coach = coach == null ? new Coach(false, DEFAULT_COACH_STATUS, Map.of()) : coach;
        continuation = continuation == null ? Continuation.defaults() : continuation;
    }

    public HamzaProperties(Metrics metrics, Policy policy, Edm edm) {
        this(metrics, policy, edm, null, null);
    }

    public HamzaProperties(Metrics metrics, Policy policy) {
        this(metrics, policy, null, null, null);
    }

    public HamzaProperties(Metrics metrics, Policy policy, Edm edm, Coach coach) {
        this(metrics, policy, edm, coach, null);
    }

    /**
     * Opt-in managed Mask-and-Continue settings. Every resource that can retain a
     * quarantined body or Mask Scope has both a useful default and a hard upper
     * bound. No invalid value is silently corrected.
     */
    public record Continuation(
            @DefaultValue("false") boolean enabled,
            @Valid @NotNull @DefaultValue Quarantine quarantine,
            @Min(1) @Max(5_000_000) @DefaultValue("50000") int candidateBudget,
            @Valid @NotNull @DefaultValue Managed managed,
            @Valid @NotNull @DefaultValue Mask mask) {

        public Continuation {
            quarantine = quarantine == null ? Quarantine.defaults() : quarantine;
            managed = managed == null ? Managed.defaults() : managed;
            mask = mask == null ? Mask.defaults() : mask;
            if (mask.maxBodyBytes() > quarantine.maxBodyBytes()) {
                throw new IllegalArgumentException("invalid-continuation-mask-admission");
            }
            if (candidateBudget <= 0 || candidateBudget > 5_000_000) {
                throw new IllegalArgumentException("invalid-continuation-candidate-budget");
            }
            if (enabled && (managed.decodedSigningKey().isEmpty()
                    || managed.approvedProfiles().isEmpty())) {
                throw new IllegalArgumentException("invalid-continuation-managed-admission");
            }
        }

        static Continuation defaults() {
            return new Continuation(false, Quarantine.defaults(),
                    DEFAULT_CONTINUATION_CANDIDATE_BUDGET,
                    Managed.defaults(), Mask.defaults());
        }
    }

    /**
     * Managed masking bounds. A Turn above either bound cannot be masked safely and
     * Blocks with Coach, so both are settings rather than constants: an operator must
     * be able to admit the Turn sizes their Agents actually send.
     */
    public record Mask(
            @Min(1) @Max(8_388_608) @DefaultValue("1048576") int maxBodyBytes,
            @Min(1) @Max(8_192) @DefaultValue("1024") int maxSegments) {

        public Mask {
            if (maxBodyBytes <= 0 || maxBodyBytes > 8 * 1024 * 1024
                    || maxSegments <= 0 || maxSegments > 8_192) {
                throw new IllegalArgumentException("invalid-continuation-mask");
            }
        }

        static Mask defaults() {
            return new Mask(DEFAULT_MASK_MAX_BODY_BYTES, DEFAULT_MASK_MAX_SEGMENTS);
        }
    }

    /** Complete-body quarantine admission bounds for the managed route. */
    public record Quarantine(
            @Min(1) @Max(67_108_864) @DefaultValue("8388608") long maxBodyBytes,
            @Min(1) @Max(2_147_483_648L) @DefaultValue("67108864") long maxTotalMemoryBytes,
            @Min(1) @Max(256) @DefaultValue("8") int maxConcurrentTurns) {

        public Quarantine {
            if (maxBodyBytes <= 0 || maxBodyBytes > 64L * 1024 * 1024
                    || maxTotalMemoryBytes < maxBodyBytes
                    || maxTotalMemoryBytes > 2L * 1024 * 1024 * 1024
                    || maxConcurrentTurns <= 0 || maxConcurrentTurns > 256) {
                throw new IllegalArgumentException("invalid-continuation-quarantine");
            }
        }

        static Quarantine defaults() {
            return new Quarantine(DEFAULT_CONTINUATION_MAX_BODY_BYTES,
                    DEFAULT_CONTINUATION_TOTAL_MEMORY_BYTES, DEFAULT_CONTINUATION_CONCURRENCY);
        }
    }

    /**
     * Signed managed-admission configuration. The base64 key is accepted only at
     * this binding seam; {@link #toString()} always redacts it and decoded callers
     * receive a fresh array.
     */
    public record Managed(
            @Size(max = 1024) @DefaultValue("") String signingKeyBase64,
            @NotNull @DefaultValue("5m") Duration maxAge,
            @NotNull @DefaultValue("30s") Duration maxFutureSkew,
            @Valid @Size(max = 64) List<ApprovedProfile> approvedProfiles) {

        public Managed {
            signingKeyBase64 = signingKeyBase64 == null ? "" : signingKeyBase64;
            approvedProfiles = approvedProfiles == null ? List.of() : List.copyOf(approvedProfiles);
            if (signingKeyBase64.length() > 1024
                    || !boundedPositive(maxAge, Duration.ofMinutes(15))
                    || !boundedPositive(maxFutureSkew, Duration.ofMinutes(5))
                    || approvedProfiles.size() > 64) {
                throw new IllegalArgumentException("invalid-continuation-managed-settings");
            }
            validateKey(signingKeyBase64);
            Set<String> identities = new HashSet<>();
            for (ApprovedProfile profile : approvedProfiles) {
                if (profile == null || !identities.add(profile.id() + ':' + profile.version())) {
                    throw new IllegalArgumentException("invalid-continuation-approved-profiles");
                }
                profile.toDomain();
            }
        }

        static Managed defaults() {
            return new Managed("", Duration.ofMinutes(5), Duration.ofSeconds(30), List.of());
        }

        public Optional<byte[]> decodedSigningKey() {
            if (signingKeyBase64.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(Base64.getDecoder().decode(signingKeyBase64).clone());
        }

        @Override
        public String toString() {
            return "Managed[signingKeyBase64="
                    + (signingKeyBase64.isEmpty() ? "<absent>" : "<redacted>")
                    + ", maxAge=" + maxAge
                    + ", maxFutureSkew=" + maxFutureSkew
                    + ", approvedProfiles=" + approvedProfiles + ']';
        }

        private static void validateKey(String encoded) {
            if (encoded.isEmpty()) {
                return;
            }
            try {
                int bytes = Base64.getDecoder().decode(encoded).length;
                if (bytes < 32 || bytes > 64) {
                    throw new IllegalArgumentException("invalid-continuation-managed-key");
                }
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("invalid-continuation-managed-key");
            }
        }
    }

    /** One version-certified, outbound-only workflow profile. */
    public record ApprovedProfile(
            @Pattern(regexp = "[a-z0-9][a-z0-9-]{0,62}") String id,
            @Min(1) int version,
            @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}") String agent,
            @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}") String provider,
            @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}") String model,
            @Pattern(regexp = "[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}") String adapterWireVersion,
            @Pattern(regexp = "[a-z0-9][a-z0-9-]{0,62}") String recipeId,
            @Min(1) int recipeVersion,
            @NotNull WorkflowShape shape) {

        public WorkflowProfile toDomain() {
            return new WorkflowProfile(id, version, agent, provider, model,
                    adapterWireVersion, recipeId, recipeVersion, shape);
        }
    }

    private static boolean boundedPositive(Duration value, Duration maximum) {
        return value != null && !value.isZero() && !value.isNegative()
                && value.compareTo(maximum) <= 0;
    }

    /**
     * @param registryDir directory of fingerprint-registry JSON files. The normal path
     *                    is the authenticated admin ingestion endpoint; the break-glass
     *                    path is {@code scripts/edm-index.py}. Empty/null disables EDM.
     *                    The Gate holds only salted one-way fingerprints, never raw
     *                    values after ingest.
     * @param blockThreshold distinct fingerprint matches from ONE registry in one scan
     *                       window required before the registry's configured Action may
     *                       escalate beyond FLAG. Below the threshold a match only FLAGs.
     * @param keepPrevious keep the previous full Registry version matchable alongside
     *                     the current one after a push. Delete always removes both.
     * @param adminToken bearer token for the internal ingestion admin API. Empty/null
     *                   disables the API.
     */
    public record Edm(String registryDir, int blockThreshold, boolean keepPrevious,
                      String adminToken, int maxContinuationEntries) {
        public Edm(String registryDir, int blockThreshold, boolean keepPrevious,
                   String adminToken) {
            this(registryDir, blockThreshold, keepPrevious, adminToken,
                    DEFAULT_EDM_MAX_CONTINUATION_ENTRIES);
        }

        @org.springframework.boot.context.properties.bind.ConstructorBinding
        public Edm {
            blockThreshold = blockThreshold > 0 ? blockThreshold : DEFAULT_EDM_BLOCK_THRESHOLD;
            adminToken = adminToken == null || adminToken.isBlank() ? null : adminToken;
            maxContinuationEntries = maxContinuationEntries > 0 ? maxContinuationEntries
                    : DEFAULT_EDM_MAX_CONTINUATION_ENTRIES;
        }

        public boolean enabled() {
            return registryDir != null && !registryDir.isBlank();
        }

        public boolean adminEnabled() {
            return adminToken != null && !adminToken.isBlank();
        }
    }

    /**
     * How a Block presents itself to the Agent (Coach). Coach never changes
     * whether a Turn is blocked or which rule blocked it; it only replaces the opaque
     * text 403 with a Provider-shaped, model-legible body that names the rule class only.
     *
     * @param enabled   opt-in: when false (default) a Block emits the bare text 403
     *                  exactly as before (the R3.1 control arm and the bare-403 fallback)
     * @param status    HTTP status of the coach response (default 403). Configurable so a
     *                  deployment can experiment with a Provider-shaped 200-message body
     *                  without a rebuild; the block decision is unchanged either way.
     * @param templates optional per-Provider message-template overrides keyed by Provider
     *                  name (e.g. {@code openai}, {@code anthropic}) or {@code default};
     *                  {@code {rules}} is replaced with the content-free rule-class list.
     */
    public record Coach(boolean enabled, int status, Map<String, String> templates) {
        public Coach {
            status = status > 0 ? status : DEFAULT_COACH_STATUS;
            templates = templates == null ? Map.of() : Map.copyOf(templates);
        }
    }

    /**
     * @param posture     the default Action for any matched rule (default {@link Action#FLAG}:
     *                    observe before enforce)
     * @param ruleActions per-rule Action overrides, keyed by rule name (e.g.
     *                    {@code aws-access-token: BLOCK})
     * @param maxBodyBytes request-body inspection cap; larger bodies have their buffered
     *                     prefix inspected and are marked {@code oversize}
     * @param controlPlanePaths known large control-plane paths that bypass body inspection
     * @param streamOversize when true (the default), over-cap bodies
     *                       are streamed to the Gate chunk by chunk and scanned
     *                       end-to-end (overlap-aware); false falls back to the
     *                       the earlier prefix-only behavior.
     */
    public record Policy(Action posture, Map<String, Action> ruleActions,
                         int maxBodyBytes, List<String> controlPlanePaths,
                         boolean streamOversize) {
        public Policy {
            posture = posture == null ? Action.FLAG : posture;
            ruleActions = ruleActions == null ? Map.of() : Map.copyOf(ruleActions);
            maxBodyBytes = maxBodyBytes > 0 ? maxBodyBytes : DEFAULT_MAX_BODY_BYTES;
            controlPlanePaths = controlPlanePaths == null ? DEFAULT_CONTROL_PLANE_PATHS : List.copyOf(controlPlanePaths);
        }
    }

    /**
     * @param modelContextTokens optional model → context-window size (tokens), used to
     *                           derive {@code hamza_context_fill_percent}. Empty by
     *                           default (the gauge is simply not emitted for unknown
     *                           models — we never fabricate a window).
     */
    public record Metrics(Map<String, Integer> modelContextTokens) {
        public Metrics {
            modelContextTokens = modelContextTokens == null ? Map.of() : Map.copyOf(modelContextTokens);
        }
    }
}
