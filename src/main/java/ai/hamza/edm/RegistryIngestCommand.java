package ai.hamza.edm;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static ai.hamza.edm.RegistryIngestionException.Kind.BAD_REQUEST;

/** Immutable, validated command for one legacy or typed Registry ingestion. */
public record RegistryIngestCommand(
        String registry,
        List<String> columns,
        Map<String, ReplacementKind> replacementKinds,
        RegistryRecipe recipe,
        int blockThreshold) {

    public static final String INVALID_REQUEST = "invalid-registry-ingest-request";
    private static final Set<String> ALLOWED_PARAMETERS = Set.of(
            "columns", "replacementKinds", "recipe", "blockThreshold");
    private static final Set<String> TYPED_PARAMETERS = Set.of(
            "replacementKinds", "recipe", "blockThreshold");
    private static final Pattern FIELD_ID = Pattern.compile("[a-z0-9][a-z0-9_-]{0,62}");
    private static final int MAX_TYPED_FIELDS = 64;
    private static final int MAX_PARAMETER_CHARS = 4096;

    public RegistryIngestCommand {
        columns = columns == null ? List.of() : List.copyOf(columns);
        replacementKinds = replacementKinds == null ? Map.of() : Map.copyOf(replacementKinds);
        if (recipe == null) {
            if (!replacementKinds.isEmpty() || blockThreshold != 0) {
                throw invalid();
            }
        } else if (columns.isEmpty() || replacementKinds.size() != columns.size()
                || blockThreshold != 1 || !recipe.equals(new RegistryRecipe("synthetic-email", 1))) {
            throw invalid();
        }
    }

    public boolean typed() {
        return recipe != null;
    }

    public static RegistryIngestCommand legacy(String registry, String columns) {
        return new RegistryIngestCommand(registry, splitColumns(columns, false),
                Map.of(), null, 0);
    }

    public static RegistryIngestCommand fromQuery(String registry,
                                                  Map<String, ? extends List<String>> query) {
        Map<String, ? extends List<String>> safe = query == null ? Map.of() : query;
        if (!ALLOWED_PARAMETERS.containsAll(safe.keySet())
                || safe.values().stream().anyMatch(values -> values == null || values.size() != 1
                || values.getFirst() == null || values.getFirst().length() > MAX_PARAMETER_CHARS)) {
            throw invalid();
        }
        boolean typed = safe.keySet().stream().anyMatch(TYPED_PARAMETERS::contains);
        if (!typed) {
            return legacy(registry, single(safe, "columns"));
        }
        if (!safe.keySet().equals(ALLOWED_PARAMETERS)) {
            throw invalid();
        }

        List<String> columns = splitColumns(single(safe, "columns"), true);
        Map<String, ReplacementKind> kinds = parseKinds(single(safe, "replacementKinds"), columns);
        RegistryRecipe recipe = parseRecipe(single(safe, "recipe"));
        int threshold = parseThreshold(single(safe, "blockThreshold"));
        return new RegistryIngestCommand(registry, columns, kinds, recipe, threshold);
    }

    private static String single(Map<String, ? extends List<String>> query, String name) {
        List<String> values = query.get(name);
        return values == null || values.isEmpty() ? null : values.getFirst();
    }

    private static List<String> splitColumns(String value, boolean strict) {
        if (value == null || value.isBlank()) {
            if (strict) {
                throw invalid();
            }
            return List.of();
        }
        List<String> columns = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String raw : value.split(",", -1)) {
            String column = raw.trim();
            if (column.isBlank() || (strict && (!FIELD_ID.matcher(column).matches() || !seen.add(column)))) {
                throw invalid();
            }
            if (!strict) {
                seen.add(column);
            }
            columns.add(column);
        }
        if (strict && columns.size() > MAX_TYPED_FIELDS) {
            throw invalid();
        }
        return List.copyOf(columns);
    }

    private static Map<String, ReplacementKind> parseKinds(String value, List<String> columns) {
        if (value == null || value.isBlank()) {
            throw invalid();
        }
        Map<String, ReplacementKind> kinds = new LinkedHashMap<>();
        for (String raw : value.split(",", -1)) {
            String[] parts = raw.split(":", -1);
            if (parts.length != 2 || !columns.contains(parts[0]) || kinds.containsKey(parts[0])) {
                throw invalid();
            }
            ReplacementKind kind;
            try {
                kind = ReplacementKind.valueOf(parts[1]);
            } catch (IllegalArgumentException e) {
                throw invalid();
            }
            kinds.put(parts[0], kind);
        }
        if (!kinds.keySet().equals(new LinkedHashSet<>(columns))) {
            throw invalid();
        }
        return Map.copyOf(kinds);
    }

    private static RegistryRecipe parseRecipe(String value) {
        if (value == null) {
            throw invalid();
        }
        String[] parts = value.split(":", -1);
        if (parts.length != 2) {
            throw invalid();
        }
        try {
            return new RegistryRecipe(parts[0], Integer.parseInt(parts[1]));
        } catch (IllegalArgumentException e) {
            throw invalid();
        }
    }

    private static int parseThreshold(String value) {
        try {
            int threshold = Integer.parseInt(value);
            if (threshold != 1) {
                throw invalid();
            }
            return threshold;
        } catch (NumberFormatException e) {
            throw invalid();
        }
    }

    private static RegistryIngestionException invalid() {
        return new RegistryIngestionException(BAD_REQUEST, INVALID_REQUEST);
    }
}
