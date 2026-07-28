package ai.hamza.config;

import ai.hamza.attest.RecordHasher;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Canonical content-free digest of every enforcement and rollout setting. */
public final class EffectiveConfigFingerprint {

    private EffectiveConfigFingerprint() {
    }

    public static String of(HamzaProperties properties) {
        java.util.Objects.requireNonNull(properties, "properties");
        HamzaProperties.Policy policy = properties.policy();
        Map<String, String> actions = new TreeMap<>();
        policy.ruleActions().forEach((rule, action) -> actions.put(rule, action.name()));
        String base = RecordHasher.configFingerprint(
                policy.posture().name(), actions, policy.maxBodyBytes(),
                policy.streamOversize(), policy.controlPlanePaths(),
                properties.edm().blockThreshold(), properties.edm().enabled());

        StringBuilder canonical = new StringBuilder(1024);
        field(canonical, "hamza-effective-config/v4");
        field(canonical, base);
        field(canonical, properties.edm().keepPrevious());
        field(canonical, properties.edm().maxContinuationEntries());

        HamzaProperties.Continuation continuation = properties.continuation();
        field(canonical, continuation.enabled());
        field(canonical, continuation.candidateBudget());
        var quarantine = continuation.quarantine();
        field(canonical, quarantine.maxBodyBytes());
        field(canonical, quarantine.maxTotalMemoryBytes());
        field(canonical, quarantine.maxConcurrentTurns());
        field(canonical, continuation.mask().maxBodyBytes());
        field(canonical, continuation.mask().maxSegments());

        HamzaProperties.Managed managed = continuation.managed();
        field(canonical, managed.decodedSigningKey().isPresent());
        field(canonical, managed.maxAge());
        field(canonical, managed.maxFutureSkew());
        List<HamzaProperties.ApprovedProfile> profiles = new ArrayList<>(
                managed.approvedProfiles());
        profiles.sort(Comparator.comparing(HamzaProperties.ApprovedProfile::id)
                .thenComparingInt(HamzaProperties.ApprovedProfile::version));
        for (var profile : profiles) {
            field(canonical, profile.id());
            field(canonical, profile.version());
            field(canonical, profile.agent());
            field(canonical, profile.provider());
            field(canonical, profile.model());
            field(canonical, profile.adapterWireVersion());
            field(canonical, profile.recipeId());
            field(canonical, profile.recipeVersion());
            field(canonical, profile.shape());
        }
        return RecordHasher.sha256Hex(canonical.toString());
    }

    private static void field(StringBuilder canonical, Object value) {
        String text = String.valueOf(value);
        canonical.append(text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length)
                .append(':').append(text).append('\n');
    }
}
