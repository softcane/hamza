package ai.hamza.adapter;

import ai.hamza.attest.PolicyArtifactCompiler;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite:${java.io.tmpdir}/hamza-adapter-registry-${random.uuid}.db",
        "spring.grpc.server.port=0",
        "server.port=0"
})
class AdapterRegistryDriftTest {

    @Autowired
    private List<ProviderAdapter> liveAdapters;

    @Test
    void compiledRegistryMatchesLiveAdapterBeans() {
        assertThat(AdapterRegistry.drift(liveAdapters).ok()).isTrue();
    }

    @Test
    void policyArtifactsContainEveryLiveAdapterDomainAndPath() {
        var artifacts = PolicyArtifactCompiler.compile(
                liveAdapters.stream().map(ProviderAdapter::spec).toList(),
                "2026-07-06T00:00:00Z");

        for (ProviderAdapter adapter : liveAdapters) {
            ProviderSpec spec = adapter.spec();
            for (String domain : spec.domains()) {
                assertThat(artifacts.ciliumYaml()).contains("matchName: " + domain);
                assertThat(artifacts.firewallDomains()).contains(domain);
                assertThat(artifacts.envoyAclYaml()).contains(domain);
            }
            for (String path : spec.paths()) {
                assertThat(artifacts.envoyAclYaml()).contains(path);
            }
        }
    }
}
