package ai.hamza.extproc;

import com.google.protobuf.ByteString;
import io.envoyproxy.envoy.config.core.v3.HeaderMap;
import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.service.ext_proc.v3.HttpHeaders;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RequestHeaderViewTest {

    @Test
    void providerAuthorizationIsNeverCopiedWhileManagedDuplicatesRemainVisible() {
        HttpHeaders headers = HttpHeaders.newBuilder().setHeaders(HeaderMap.newBuilder()
                .addHeaders(header(":path", "/v1/responses"))
                .addHeaders(rawHeader("authorization", "Bearer fixture-provider-token"))
                .addHeaders(header("proxy-authorization", "fixture-proxy-token"))
                .addHeaders(header("x-api-key", "fixture-anthropic-provider-token"))
                .addHeaders(header("cookie", "provider_session=fixture-cookie-token"))
                .addHeaders(header("user-agent", "codex_cli_rs/1.0"))
                .addHeaders(header("x-hamza-agent", "codex"))
                .addHeaders(header("X-Hamza-Agent", "duplicate")))
                .build();

        RequestHeaderView view = RequestHeaderView.from(headers);

        assertThat(view.routingHeaders())
                .containsEntry(":path", "/v1/responses")
                .containsEntry("user-agent", "codex_cli_rs/1.0")
                .doesNotContainKeys("authorization", "proxy-authorization", "x-api-key",
                        "cookie", "x-hamza-agent");
        assertThat(view.managedHeaders()).containsEntry("x-hamza-agent", java.util.List.of(
                "codex", "duplicate"));
        assertThat(view.toString())
                .doesNotContain("fixture-provider-token", "fixture-proxy-token",
                        "fixture-anthropic-provider-token", "fixture-cookie-token", "codex")
                .contains("routing=2", "managed=2");
    }

    @Test
    void routeProviderHintIsSeparatedFromSignedManagedMetadataAndMustBeSingular() {
        RequestHeaderView singular = RequestHeaderView.from(HttpHeaders.newBuilder()
                .setHeaders(HeaderMap.newBuilder()
                        .addHeaders(header(RequestHeaderView.ROUTE_PROVIDER_HEADER, "anthropic")))
                .build());

        assertThat(singular.routeProvider()).isEqualTo("anthropic");
        assertThat(singular.managedHeaders()).isEmpty();
        assertThat(singular.routingHeaders()).isEmpty();

        RequestHeaderView duplicate = RequestHeaderView.from(HttpHeaders.newBuilder()
                .setHeaders(HeaderMap.newBuilder()
                        .addHeaders(header(RequestHeaderView.ROUTE_PROVIDER_HEADER, "anthropic"))
                        .addHeaders(header(RequestHeaderView.ROUTE_PROVIDER_HEADER, "openai")))
                .build());
        assertThat(duplicate.routeProvider()).isNull();
    }

    private static HeaderValue header(String name, String value) {
        return HeaderValue.newBuilder().setKey(name).setValue(value).build();
    }

    private static HeaderValue rawHeader(String name, String value) {
        return HeaderValue.newBuilder().setKey(name)
                .setRawValue(ByteString.copyFromUtf8(value)).build();
    }
}
