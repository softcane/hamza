package ai.hamza.continuation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Verifies bounded metadata issued by the managed Agent launcher. */
public final class ManagedMetadataVerifier {

    public static final String RECOVERY_ID = "x-hamza-recovery-id";
    public static final String PROFILE_ID = "x-hamza-workflow-profile";
    public static final String PROFILE_VERSION = "x-hamza-workflow-version";
    public static final String AGENT = "x-hamza-agent";
    public static final String PROVIDER = "x-hamza-provider";
    public static final String MODEL = "x-hamza-model";
    public static final String ADAPTER_WIRE_VERSION = "x-hamza-adapter-wire-version";
    public static final String ISSUED_AT = "x-hamza-issued-at";
    public static final String SIGNATURE = "x-hamza-signature";

    private static final Set<String> INTERNAL_HEADERS = Set.of(
            RECOVERY_ID, PROFILE_ID, PROFILE_VERSION, AGENT, PROVIDER, MODEL,
            ADAPTER_WIRE_VERSION, ISSUED_AT, SIGNATURE);
    private static final int MAX_VALUE_CHARS = 256;

    private final Clock clock;
    private final Duration maxAge;
    private final Duration maxFutureSkew;
    private final byte[] key;
    private final Map<ProfileKey, WorkflowProfile> profiles;

    public ManagedMetadataVerifier(Clock clock, Duration maxAge, Duration maxFutureSkew,
                                   byte[] key, List<WorkflowProfile> profiles) {
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
        this.maxAge = positive(maxAge, "maxAge");
        this.maxFutureSkew = positive(maxFutureSkew, "maxFutureSkew");
        if (key == null || key.length < 16) {
            throw new IllegalArgumentException("managed metadata key is too short");
        }
        this.key = key.clone();
        Map<ProfileKey, WorkflowProfile> indexed = new HashMap<>();
        for (WorkflowProfile profile : profiles == null ? List.<WorkflowProfile>of() : profiles) {
            WorkflowProfile previous = indexed.put(new ProfileKey(profile.id(), profile.version()), profile);
            if (previous != null) {
                throw new IllegalArgumentException("duplicate workflow profile");
            }
        }
        this.profiles = Map.copyOf(indexed);
    }

    public ManagedMetadataDecision verify(Map<String, List<String>> suppliedHeaders) {
        Map<String, List<String>> headers = normalize(suppliedHeaders);
        boolean anyInternal = headers.keySet().stream().anyMatch(name -> name.startsWith("x-hamza-"));
        if (!anyInternal) {
            return ManagedMetadataDecision.Absent.INSTANCE;
        }
        if (headers.keySet().stream().anyMatch(name -> name.startsWith("x-hamza-")
                && !INTERNAL_HEADERS.contains(name))) {
            return invalid(ManagedMetadataReason.UNKNOWN_HEADER);
        }
        for (String name : INTERNAL_HEADERS) {
            List<String> values = headers.get(name);
            if (values == null) {
                return invalid(ManagedMetadataReason.INCOMPLETE);
            }
            if (values.size() != 1) {
                return invalid(ManagedMetadataReason.DUPLICATE);
            }
            String value = values.getFirst();
            if (value == null || value.isBlank() || value.length() > MAX_VALUE_CHARS
                    || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
                return invalid(ManagedMetadataReason.INVALID_FIELD);
            }
        }

        Map<String, String> scalar = new LinkedHashMap<>();
        INTERNAL_HEADERS.forEach(name -> scalar.put(name, headers.get(name).getFirst()));
        String expected;
        try {
            expected = ManagedMetadataSignature.sign(scalar, key);
        } catch (IllegalArgumentException e) {
            return invalid(ManagedMetadataReason.INVALID_FIELD);
        }
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                scalar.get(SIGNATURE).getBytes(StandardCharsets.US_ASCII))) {
            return invalid(ManagedMetadataReason.BAD_SIGNATURE);
        }

        final RecoveryId recoveryId;
        final int profileVersion;
        final Instant issuedAt;
        try {
            recoveryId = RecoveryId.parse(scalar.get(RECOVERY_ID));
            profileVersion = Integer.parseInt(scalar.get(PROFILE_VERSION));
            issuedAt = Instant.ofEpochSecond(Long.parseLong(scalar.get(ISSUED_AT)));
        } catch (RuntimeException e) {
            return invalid(ManagedMetadataReason.INVALID_FIELD);
        }

        Instant now = clock.instant();
        if (issuedAt.isBefore(now.minus(maxAge))) {
            return invalid(ManagedMetadataReason.EXPIRED);
        }
        if (issuedAt.isAfter(now.plus(maxFutureSkew))) {
            return invalid(ManagedMetadataReason.FUTURE);
        }
        WorkflowProfile profile = profiles.get(new ProfileKey(scalar.get(PROFILE_ID), profileVersion));
        if (profile == null) {
            return invalid(ManagedMetadataReason.PROFILE_NOT_APPROVED);
        }
        if (!profile.matchesTuple(scalar.get(AGENT), scalar.get(PROVIDER), scalar.get(MODEL),
                scalar.get(ADAPTER_WIRE_VERSION))) {
            return invalid(ManagedMetadataReason.TUPLE_NOT_APPROVED);
        }
        return new ManagedMetadataDecision.Verified(recoveryId, profile, issuedAt);
    }

    public static Set<String> internalHeaderNames() {
        return new LinkedHashSet<>(INTERNAL_HEADERS);
    }

    private static Map<String, List<String>> normalize(Map<String, List<String>> supplied) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (supplied == null) {
            return out;
        }
        supplied.forEach((name, values) -> {
            if (name == null) {
                return;
            }
            String lower = name.toLowerCase(Locale.ROOT);
            List<String> prior = out.get(lower);
            if (prior == null) {
                out.put(lower, values == null ? List.of() : List.copyOf(values));
            } else {
                java.util.ArrayList<String> merged = new java.util.ArrayList<>(prior);
                if (values != null) {
                    merged.addAll(values);
                }
                out.put(lower, List.copyOf(merged));
            }
        });
        return out;
    }

    private static Duration positive(Duration duration, String label) {
        if (duration == null || duration.isNegative() || duration.isZero()) {
            throw new IllegalArgumentException(label + " must be positive");
        }
        return duration;
    }

    private static ManagedMetadataDecision.Invalid invalid(ManagedMetadataReason reason) {
        return new ManagedMetadataDecision.Invalid(reason);
    }

    private record ProfileKey(String id, int version) {
    }
}
