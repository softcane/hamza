package ai.hamza.extproc;

import ai.hamza.adapter.OpenAiResponsesAdapter;
import ai.hamza.config.HamzaProperties;
import ai.hamza.metrics.HamzaMetrics;
import ai.hamza.persistence.TurnRepository;
import ai.hamza.policy.Action;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.Masker;
import ai.hamza.policy.SecretDetector;
import com.google.protobuf.ByteString;
import io.envoyproxy.envoy.config.core.v3.HeaderMap;
import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.service.ext_proc.v3.ExternalProcessorGrpc;
import io.envoyproxy.envoy.service.ext_proc.v3.HttpBody;
import io.envoyproxy.envoy.service.ext_proc.v3.HttpHeaders;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingRequest;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingResponse;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Decode + wire-drift invariants:
 * a gzipped body is decoded before inspection; an undecodable encoded body surfaces as
 * {@code opaque-content}; an Adapter parse failure surfaces as {@code wire-drift};
 * an encoded body is never masked (no safe span on the wire bytes).
 */
class ExternalProcessorDecodeInvariantsTest {

    private static final String AWS_KEY = "AKIAABCDEFGHIJKLMNOP";

    private JdbcClient jdbcOn(Path db) {
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + db);
        try (var conn = ds.getConnection(); var st = conn.createStatement()) {
            String schema = new String(getClass().getResourceAsStream("/schema.sql").readAllBytes());
            for (String s : schema.split(";")) {
                if (!s.isBlank()) {
                    st.execute(s);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return JdbcClient.create(ds);
    }

    private record Harness(Server server, ManagedChannel channel, TurnRepository repo,
                           SimpleMeterRegistry registry, JdbcClient jdbc) {
    }

    private Harness start(Path db, Action posture, Map<String, Action> overrides,
                          boolean streamOversize) throws Exception {
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository repo = new TurnRepository(jdbc);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        HamzaMetrics metrics = new HamzaMetrics(registry,
                new HamzaProperties(new HamzaProperties.Metrics(Map.of()),
                        new HamzaProperties.Policy(posture, overrides,
                                HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                                HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, streamOversize)));
        PolicyEngine engine = new PolicyEngine(new SecretDetector(), new Masker(), posture, overrides);
        ExternalProcessorService service = new ExternalProcessorService(
                new DefaultTurnPipeline(List.of(new OpenAiResponsesAdapter()), engine, repo, metrics,
                        new CoachSessionTracker(), new ReEncodedContentDetector(),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, streamOversize,
                        ManagedContinuationRuntime.disabled()));

        String name = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(name).directExecutor().addService(service).build().start();
        ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        return new Harness(server, channel, repo, registry, jdbc);
    }

    private void shutdown(Harness h) throws Exception {
        h.channel().shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        h.server().shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }

    private List<ProcessingResponse> exchange(ManagedChannel channel, List<ProcessingRequest> reqs) throws Exception {
        var stub = ExternalProcessorGrpc.newStub(channel);
        List<ProcessingResponse> out = new ArrayList<>();
        CountDownLatch done = new CountDownLatch(1);
        StreamObserver<ProcessingRequest> requests = stub.process(new StreamObserver<>() {
            public void onNext(ProcessingResponse v) {
                out.add(v);
            }

            public void onError(Throwable t) {
                done.countDown();
            }

            public void onCompleted() {
                done.countDown();
            }
        });
        reqs.forEach(requests::onNext);
        requests.onCompleted();
        assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        return out;
    }

    private ProcessingRequest headers(Map<String, String> hdrs) {
        HeaderMap.Builder hm = HeaderMap.newBuilder();
        hdrs.forEach((k, v) -> hm.addHeaders(HeaderValue.newBuilder()
                .setKey(k).setRawValue(ByteString.copyFromUtf8(v))));
        return ProcessingRequest.newBuilder()
                .setRequestHeaders(HttpHeaders.newBuilder().setHeaders(hm)).build();
    }

    private ProcessingRequest body(byte[] content, boolean endOfStream) {
        return ProcessingRequest.newBuilder()
                .setRequestBody(HttpBody.newBuilder()
                        .setBody(ByteString.copyFrom(content)).setEndOfStream(endOfStream)).build();
    }

    private ProcessingRequest responseHeaders() {
        HeaderMap.Builder hm = HeaderMap.newBuilder();
        hm.addHeaders(HeaderValue.newBuilder()
                .setKey(":status").setRawValue(ByteString.copyFromUtf8("200")));
        return ProcessingRequest.newBuilder()
                .setResponseHeaders(HttpHeaders.newBuilder().setHeaders(hm)).build();
    }

    private ProcessingRequest responseBody() {
        String sse = """
                event: response.completed
                data: {"type":"response.completed","response":{"model":"gpt-5-codex","status":"completed",\
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}

                data: [DONE]
                """;
        return ProcessingRequest.newBuilder()
                .setResponseBody(HttpBody.newBuilder()
                        .setBody(ByteString.copyFromUtf8(sse)).setEndOfStream(true)).build();
    }

    private static byte[] gzip(String text) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write(text.getBytes(StandardCharsets.UTF_8));
        }
        return bos.toByteArray();
    }

    private Map<String, String> gzipHeaders(int contentLength) {
        return Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                "content-encoding", "gzip",
                "content-length", Integer.toString(contentLength));
    }

    @Test
    void gzippedBodyIsDecodedBeforeInspectionAndNeverMasked(@TempDir Path tmp) throws Exception {
        // MASK posture: the secret is found in the DECODED text, but an encoded body has
        // no safe span on the wire bytes, so the match downgrades to FLAG — no mutation.
        Harness h = start(tmp.resolve("gz.db"), Action.MASK, Map.of(), false);
        try {
            byte[] gz = gzip("{\"model\":\"gpt-5-codex\",\"input\":\"key " + AWS_KEY + " end\"}");
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(gzipHeaders(gz.length)),
                    body(gz, true),
                    responseHeaders(),
                    responseBody()));

            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
            assertThat(out.get(1).getRequestBody().getResponse().hasBodyMutation()).isFalse();

            assertThat(h.jdbc().sql("SELECT action FROM turns").query(String.class).single())
                    .isEqualTo("FLAG");
            assertThat(h.jdbc().sql("SELECT rule FROM findings ORDER BY rule").query(String.class).list())
                    .containsExactly("aws-access-token");
            // Model attribution comes from the decoded body.
            assertThat(h.jdbc().sql("SELECT requested_model FROM turns").query(String.class).single())
                    .isEqualTo("gpt-5-codex");
        } finally {
            shutdown(h);
        }
    }

    @Test
    void gzippedSecretBlocksBeforeEgressWhenRuleBlocks(@TempDir Path tmp) throws Exception {
        Harness h = start(tmp.resolve("gzb.db"), Action.FLAG,
                Map.of("aws-access-token", Action.BLOCK), false);
        try {
            byte[] gz = gzip("{\"model\":\"gpt-5-codex\",\"input\":\"key " + AWS_KEY + " end\"}");
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(gzipHeaders(gz.length)),
                    body(gz, true)));

            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(out.get(1).getImmediateResponse().getStatus().getCode().getNumber()).isEqualTo(403);
        } finally {
            shutdown(h);
        }
    }

    @Test
    void corruptGzipSurfacesOpaqueContentNotASilentPass(@TempDir Path tmp) throws Exception {
        Harness h = start(tmp.resolve("corrupt.db"), Action.FLAG, Map.of(), false);
        try {
            byte[] gz = gzip("{\"model\":\"gpt-5-codex\",\"input\":\"hello\"}");
            gz[gz.length / 2] ^= 0x55; // corrupt the deflate stream
            exchange(h.channel(), List.of(
                    headers(gzipHeaders(gz.length)),
                    body(gz, true),
                    responseHeaders(),
                    responseBody()));

            assertThat(h.jdbc().sql("SELECT rule FROM findings ORDER BY rule").query(String.class).list())
                    .containsExactly(TurnState.OPAQUE_CONTENT_RULE);
        } finally {
            shutdown(h);
        }
    }

    @Test
    void adapterParseFailureSurfacesWireDrift(@TempDir Path tmp) throws Exception {
        // Truncated/invalid JSON on a matched path: the secret is still detected (the
        // scanner is format-agnostic) AND the parse failure itself is a loud Finding.
        Harness h = start(tmp.resolve("drift.db"), Action.FLAG, Map.of(), false);
        try {
            String notJson = "model=gpt-5-codex&input=key " + AWS_KEY + " {broken";
            exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "content-length", Integer.toString(notJson.length()))),
                    body(notJson.getBytes(StandardCharsets.UTF_8), true),
                    responseHeaders(),
                    responseBody()));

            assertThat(h.jdbc().sql("SELECT rule FROM findings ORDER BY rule").query(String.class).list())
                    .containsExactly("aws-access-token", TurnState.WIRE_DRIFT_RULE);
        } finally {
            shutdown(h);
        }
    }

    @Test
    void encodedStreamedOversizeBodyIsMarkedOpaque(@TempDir Path tmp) throws Exception {
        // Streaming decode is not implemented: an encoded oversize body is scanned as wire
        // bytes only, and the Record must say so.
        Harness h = start(tmp.resolve("streamgz.db"), Action.FLAG, Map.of(), true);
        try {
            byte[] chunk = gzip("{\"model\":\"gpt-5-codex\",\"input\":\"" + "x".repeat(200_000) + "\"}");
            exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "content-encoding", "gzip",
                            "content-length", Integer.toString(HamzaProperties.DEFAULT_MAX_BODY_BYTES + 1))),
                    body(chunk, true),
                    responseHeaders(),
                    responseBody()));

            assertThat(h.jdbc().sql("SELECT rule FROM findings ORDER BY rule").query(String.class).list())
                    .containsExactly(TurnState.OPAQUE_CONTENT_RULE, TurnState.OVERSIZE_RULE);
        } finally {
            shutdown(h);
        }
    }
}
