package ai.hamza.presidio;

import ai.hamza.masking.PlaceholderFamily;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The entity set M3 approved for enforcement, loaded from the recorded approved
 * profile. Only an entity that met every fixed quality floor may enforce: loading
 * refuses an entity {@link #EVALUATION_DISABLED M3 disabled}, an entity it never
 * evaluated, or a profile that contradicts itself. The disabled set lives in code,
 * so editing the profile cannot widen what may enforce.
 */
public final class PresidioProfile {

    /** Fixed Placeholder family per evaluated entity. Bounded, never derived from content. */
    private static final Map<String, PlaceholderFamily> FAMILIES = Map.ofEntries(
            Map.entry("CREDIT_CARD", PlaceholderFamily.ACCOUNT),
            Map.entry("CRYPTO", PlaceholderFamily.ACCOUNT),
            Map.entry("IBAN_CODE", PlaceholderFamily.ACCOUNT),
            Map.entry("EMAIL_ADDRESS", PlaceholderFamily.EMAIL),
            Map.entry("PHONE_NUMBER", PlaceholderFamily.PHONE),
            Map.entry("IP_ADDRESS", PlaceholderFamily.IP),
            Map.entry("MAC_ADDRESS", PlaceholderFamily.PII),
            Map.entry("MEDICAL_LICENSE", PlaceholderFamily.PII),
            Map.entry("URL", PlaceholderFamily.PII),
            Map.entry("PERSON", PlaceholderFamily.PERSON),
            Map.entry("LOCATION", PlaceholderFamily.LOCATION),
            Map.entry("NRP", PlaceholderFamily.PII),
            Map.entry("DATE_TIME", PlaceholderFamily.PII));

    /**
     * The entities the M3 evaluation disabled for missing a fixed quality floor. This
     * is recorded in code, not read from the profile, so a hand-written or truncated
     * profile cannot quietly re-enable one. Re-approving an entity requires a fresh
     * evaluation and a deliberate edit here, next to the evidence that justifies it.
     */
    private static final Set<String> EVALUATION_DISABLED =
            Set.of("DATE_TIME", "NRP", "LOCATION", "PERSON");

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String SCHEMA = "hamza-presidio-approved-profile/v1";

    private final String profileId;
    private final int version;
    private final String language;
    private final double scoreThreshold;
    private final List<String> enabledEntities;
    private final Map<String, Double> entityThresholds;

    PresidioProfile(String profileId, int version, String language, double scoreThreshold,
                    List<String> enabledEntities) {
        this(profileId, version, language, scoreThreshold, enabledEntities, Map.of());
    }

    /**
     * @param entityThresholds a per-entity override of {@code scoreThreshold}, keyed by
     *                         entity type. An entity absent here falls back to
     *                         {@code scoreThreshold}. Every key must name an entity in
     *                         {@code enabledEntities} and every value must be a valid
     *                         {@code [0.0, 1.0]} threshold.
     */
    PresidioProfile(String profileId, int version, String language, double scoreThreshold,
                    List<String> enabledEntities, Map<String, Double> entityThresholds) {
        this.profileId = requireBounded(profileId, "profileId");
        if (version < 1) {
            throw new IllegalArgumentException("profile version must be positive");
        }
        this.version = version;
        this.language = requireBounded(language, "language");
        if (!Double.isFinite(scoreThreshold) || scoreThreshold < 0.0 || scoreThreshold > 1.0) {
            throw new IllegalArgumentException("score threshold must be between zero and one");
        }
        this.scoreThreshold = scoreThreshold;
        Set<String> unique = new LinkedHashSet<>(
                Objects.requireNonNull(enabledEntities, "enabledEntities"));
        if (unique.isEmpty()) {
            throw new IllegalArgumentException("an enabled profile requires an approved entity");
        }
        for (String entity : unique) {
            if (!FAMILIES.containsKey(entity)) {
                throw new IllegalArgumentException("unevaluated Presidio entity: " + entity);
            }
            if (EVALUATION_DISABLED.contains(entity)) {
                throw new IllegalArgumentException(
                        "the M3 evaluation disabled this Presidio entity: " + entity);
            }
        }
        this.enabledEntities = List.copyOf(unique);
        Objects.requireNonNull(entityThresholds, "entityThresholds");
        for (Map.Entry<String, Double> override : entityThresholds.entrySet()) {
            String entity = override.getKey();
            double value = override.getValue();
            if (!Double.isFinite(value) || value < 0.0 || value > 1.0) {
                throw new IllegalArgumentException(
                        "per-entity threshold for " + entity + " must be between zero and one");
            }
            if (!this.enabledEntities.contains(entity)) {
                throw new IllegalArgumentException(
                        "per-entity threshold names an entity absent from enabled_entities: "
                                + entity);
            }
        }
        this.entityThresholds = Map.copyOf(entityThresholds);
    }

    /**
     * Reads the recorded M3 approved profile.
     *
     * @param path the approved profile written by the M3 feasibility evaluation
     * @return the approved entity set
     */
    public static PresidioProfile load(Path path) {
        Objects.requireNonNull(path, "path");
        JsonNode root;
        try {
            root = JSON.readTree(Files.readString(path));
        } catch (IOException e) {
            throw new UncheckedIOException("unreadable Presidio approved profile", e);
        }
        if (!SCHEMA.equals(root.path("schema").asText())) {
            throw new IllegalArgumentException("unknown approved profile schema");
        }
        List<String> enabled = texts(root.path("enabled_entities"));
        Set<String> disabled = new LinkedHashSet<>();
        root.path("disabled_entities").forEach(entry ->
                disabled.add(entry.path("entity").asText()));
        for (String entity : enabled) {
            if (disabled.contains(entity)) {
                throw new IllegalArgumentException(
                        "M3 disabled this Presidio entity: " + entity);
            }
        }
        Map<String, Double> entityThresholds = new LinkedHashMap<>();
        JsonNode overrides = root.path("entity_thresholds");
        overrides.fieldNames().forEachRemaining(name ->
                entityThresholds.put(name, overrides.path(name).asDouble(-1.0)));
        return new PresidioProfile(root.path("profile_id").asText(),
                root.path("version").asInt(), root.path("language").asText(),
                root.path("selected_threshold").asDouble(-1.0), enabled, entityThresholds);
    }

    /**
     * Maps an entity to its bounded, detector-qualified rule identifier.
     *
     * @param entity a Presidio entity type
     * @return the fixed rule identifier used by policy, metrics, and Records
     */
    public static String rule(String entity) {
        return Objects.requireNonNull(entity, "entity")
                .toLowerCase(Locale.ROOT).replace('_', '-');
    }

    /**
     * Returns the fixed Placeholder family for an approved entity.
     *
     * @param entity a Presidio entity type
     * @return the family used to render the stable Placeholder
     */
    public PlaceholderFamily family(String entity) {
        PlaceholderFamily family = FAMILIES.get(entity);
        if (family == null) {
            throw new IllegalArgumentException("unevaluated Presidio entity: " + entity);
        }
        return family;
    }

    public boolean enabled(String entity) {
        return enabledEntities.contains(entity);
    }

    public List<String> enabledEntities() {
        return enabledEntities;
    }

    public double scoreThreshold() {
        return scoreThreshold;
    }

    /**
     * The score threshold that applies to one entity: its own override if the profile
     * names one, otherwise the profile's {@link #scoreThreshold()}.
     *
     * @param entity a Presidio entity type
     * @return the effective threshold a raw Finding for that entity must meet
     */
    public double threshold(String entity) {
        return entityThresholds.getOrDefault(entity, scoreThreshold);
    }

    /**
     * The lowest effective threshold across every enabled entity: the profile's default
     * where an entity has no override, and the override itself where it does. This is
     * the wire value the Analyzer request must use so it never filters out a Finding a
     * per-entity override would otherwise admit.
     *
     * @return the minimum score threshold across all enabled entities
     */
    public double minimumThreshold() {
        double minimum = scoreThreshold;
        for (double override : entityThresholds.values()) {
            minimum = Math.min(minimum, override);
        }
        return minimum;
    }

    public String language() {
        return language;
    }

    /** Bounded content-free detector version, safe for Records and metric labels. */
    public String detectorVersion() {
        return "presidio:" + profileId + ":v" + version;
    }

    private static List<String> texts(JsonNode values) {
        List<String> result = new java.util.ArrayList<>();
        values.forEach(value -> result.add(value.asText()));
        return List.copyOf(result);
    }

    private static String requireBounded(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 64
                || !value.matches("[A-Za-z0-9][A-Za-z0-9._-]*")) {
            throw new IllegalArgumentException(name + " must be a bounded identifier");
        }
        return value;
    }

    @Override
    public String toString() {
        return "PresidioProfile[" + detectorVersion() + ", entities=" + enabledEntities.size()
                + ", threshold=" + scoreThreshold + ']';
    }
}
