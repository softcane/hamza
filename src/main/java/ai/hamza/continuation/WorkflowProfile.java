package ai.hamza.continuation;

import java.util.Objects;
import java.util.regex.Pattern;

/** Content-free, administrator-approved Safe Continuation workflow metadata. */
public record WorkflowProfile(
        String id,
        int version,
        String agent,
        String provider,
        String model,
        String adapterWireVersion,
        String recipeId,
        int recipeVersion,
        WorkflowShape shape) {

    private static final Pattern ID = Pattern.compile("[a-z0-9][a-z0-9-]{0,62}");
    private static final Pattern TUPLE = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}");

    public WorkflowProfile {
        require(ID, id, "profile id");
        require(TUPLE, agent, "agent");
        require(TUPLE, provider, "provider");
        require(TUPLE, model, "model");
        require(TUPLE, adapterWireVersion, "adapter wire version");
        require(ID, recipeId, "recipe id");
        if (version <= 0 || recipeVersion <= 0) {
            throw new IllegalArgumentException("versions must be positive");
        }
        shape = Objects.requireNonNull(shape, "shape");
    }

    boolean matchesTuple(String suppliedAgent, String suppliedProvider, String suppliedModel,
                         String suppliedWireVersion) {
        return agent.equals(suppliedAgent)
                && provider.equals(suppliedProvider)
                && model.equals(suppliedModel)
                && adapterWireVersion.equals(suppliedWireVersion);
    }

    private static void require(Pattern pattern, String value, String label) {
        if (value == null || !pattern.matcher(value).matches()) {
            throw new IllegalArgumentException("invalid " + label);
        }
    }
}
