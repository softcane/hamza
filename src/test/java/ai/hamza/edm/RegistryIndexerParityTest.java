package ai.hamza.edm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class RegistryIndexerParityTest {

    @Test
    void javaLoadsAndMatchesThePythonV2ParityFixture(@TempDir Path registryDir) throws Exception {
        try (InputStream fixture = getClass().getResourceAsStream("/edm/python-v2-parity.json")) {
            assertThat(fixture).isNotNull();
            Files.copy(fixture, registryDir.resolve("customers.json"));
        }

        RegistryStore store = new RegistryStore(registryDir, 10);

        assertThat(store.typedRegistries()).singleElement().satisfies(registry -> {
            assertThat(registry.version()).isEqualTo(RegistryCanonicalizer.versionDigest(
                    registry.id(), registry.salt(), registry.blockThreshold(),
                    registry.recipe(), registry.fields()));
            assertThat(registry.fields().get("email").fingerprints()).contains(
                    Fingerprinter.fullFingerprint(registry.salt(),
                            Fingerprinter.normalize("Fake101@Example-Corp.Test")),
                    Fingerprinter.fullFingerprint(registry.salt(),
                            Fingerprinter.normalize("cafe\u0301@example-corp.test")));
        });
    }
}
