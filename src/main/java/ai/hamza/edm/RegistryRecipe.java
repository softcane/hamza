package ai.hamza.edm;

import java.util.regex.Pattern;

/** Immutable reference to one approved, versioned replacement recipe. */
public record RegistryRecipe(String id, int version) {

    private static final Pattern ID = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");

    public RegistryRecipe {
        if (id == null || !ID.matcher(id).matches() || version <= 0) {
            throw new IllegalArgumentException("invalid-registry-recipe");
        }
    }
}
