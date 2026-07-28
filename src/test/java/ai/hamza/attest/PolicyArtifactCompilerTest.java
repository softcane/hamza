package ai.hamza.attest;

import ai.hamza.adapter.AdapterRegistry;
import ai.hamza.adapter.OpenAiResponsesAdapter;
import ai.hamza.adapter.ProviderAdapter;
import ai.hamza.adapter.ProviderSpec;
import ai.hamza.adapter.RequestView;
import ai.hamza.adapter.NormalizedTurn;
import ai.hamza.adapter.TurnDraft;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PolicyArtifactCompilerTest {

    @Test
    void compilerEmitsAllArtifactShapesFromAdapterRegistry() {
        var artifacts = PolicyArtifactCompiler.compile(AdapterRegistry.defaultSpecs(),
                "2026-07-06T00:00:00Z");

        assertThat(artifacts.ciliumYaml())
                .contains("kind: CiliumNetworkPolicy")
                .contains("matchName: api.openai.com")
                .contains("matchName: chatgpt.com")
                .contains("matchName: api.anthropic.com");
        assertThat(artifacts.firewallDomains())
                .contains("api.openai.com")
                .contains("chatgpt.com")
                .contains("api.anthropic.com");
        assertThat(artifacts.envoyAclYaml())
                .contains("provider: openai")
                .contains("chatgpt.com")
                .contains("/v1/responses")
                .contains("provider: anthropic")
                .contains("/v1/messages");
    }

    @Test
    void driftDetectionFailsWhenLiveAdapterIsMissingFromRegistry() {
        ProviderAdapter newAdapter = new ProviderAdapter() {
            @Override
            public String provider() {
                return "new-provider";
            }

            @Override
            public ProviderSpec spec() {
                return new ProviderSpec("new-provider", List.of("api.new-provider.test"),
                        List.of("/v1/new"));
            }

            @Override
            public boolean matches(String path, Map<String, String> headers) {
                return false;
            }

            @Override
            public RequestView parseRequest(byte[] body) {
                return RequestView.empty();
            }

            @Override
            public NormalizedTurn finalizeTurn(TurnDraft draft) {
                throw new UnsupportedOperationException();
            }
        };

        var drift = AdapterRegistry.drift(List.of(new OpenAiResponsesAdapter(), newAdapter));

        assertThat(drift.ok()).isFalse();
        assertThat(drift.missingFromRegistry()).contains("new-provider");
        assertThat(drift.staleInRegistry()).contains("anthropic");
    }
}
