package ai.hamza.edm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class EdmFpHarnessTest {

    private RegistryStore store() throws Exception {
        return new RegistryStore(Path.of(getClass().getResource("/edm").toURI()));
    }

    @Test
    void benignCorpusProducesZeroWouldBlockWindows(@TempDir Path corpus) throws Exception {
        Files.writeString(corpus.resolve("code.java"),
                "public class Foo { void run() { parser.parse(input); } }");
        Files.writeString(corpus.resolve("notes.md"),
                "deploy the gateway, then check grafana and the flaky integration test");

        EdmFpHarness.Report report = EdmFpHarness.run(store(), corpus, 10, 65_536);

        assertThat(report.files()).isEqualTo(2);
        EdmFpHarness.RegistryStats stats = report.registries().get("customers");
        assertThat(stats.wouldBlockWindows).isZero();
        assertThat(stats.windowsWithMatch).isZero();
    }

    @Test
    void leakyFileIsReportedAsWouldBlockWithItsPath(@TempDir Path corpus) throws Exception {
        StringBuilder leaky = new StringBuilder("debug dump: ");
        for (int i = 1; i <= 12; i++) {
            leaky.append("fake%03d@example-corp.test ".formatted(i));
        }
        Files.writeString(corpus.resolve("dump.txt"), leaky.toString());
        Files.writeString(corpus.resolve("benign.txt"), "nothing sensitive here at all");

        EdmFpHarness.Report report = EdmFpHarness.run(store(), corpus, 10, 65_536);

        EdmFpHarness.RegistryStats stats = report.registries().get("customers");
        assertThat(stats.wouldBlockWindows).isEqualTo(1);
        assertThat(stats.maxDistinct).isEqualTo(12);
        assertThat(stats.wouldBlockFiles).hasSize(1);
        assertThat(stats.wouldBlockFiles.getFirst()).contains("dump.txt");
    }

    @Test
    void belowThresholdMatchesAreCountedButNotBlocking(@TempDir Path corpus) throws Exception {
        Files.writeString(corpus.resolve("three.txt"),
                "fake001@example-corp.test fake002@example-corp.test fake003@example-corp.test");

        EdmFpHarness.Report report = EdmFpHarness.run(store(), corpus, 10, 65_536);

        EdmFpHarness.RegistryStats stats = report.registries().get("customers");
        assertThat(stats.windowsWithMatch).isEqualTo(1);
        assertThat(stats.maxDistinct).isEqualTo(3);
        assertThat(stats.wouldBlockWindows).isZero();
    }
}
