package ai.hamza.edm;

import java.util.List;

/** Content-free admin view of loaded/persisted Registry versions. */
public record RegistryStats(String registry, List<RegistryVersionStats> versions) {

    public record RegistryVersionStats(String version, long distinctFingerprints,
                                       boolean current) {
    }
}
