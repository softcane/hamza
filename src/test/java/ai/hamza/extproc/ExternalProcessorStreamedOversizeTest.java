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
import io.envoyproxy.envoy.extensions.filters.http.ext_proc.v3.ProcessingMode;
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

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M7 spike: with {@code hamza.policy.stream-oversize=true}, an over-cap body is streamed
 * to the Gate chunk by chunk and scanned end-to-end — a secret deep in the tail (beyond
 * the old buffered prefix) or spanning a chunk boundary is caught, and a mid-stream
 * BLOCK stops the remainder while recording {@code partial-egress} honestly.
 */
class ExternalProcessorStreamedOversizeTest {

    private static final String AWS_KEY = "AKIAABCDEFGHIJKLMNOP";
    /** Chunks larger than the 4 KiB overlap prove the scan window is NOT the whole body. */
    private static final int CHUNK = 40_000;

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

    private Harness start(Path db, Action posture, Map<String, Action> overrides) throws Exception {
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository repo = new TurnRepository(jdbc);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        HamzaMetrics metrics = new HamzaMetrics(registry,
                new HamzaProperties(new HamzaProperties.Metrics(Map.of()),
                        new HamzaProperties.Policy(posture, overrides,
                                HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                                HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true)));
        PolicyEngine engine = new PolicyEngine(new SecretDetector(), new Masker(), posture, overrides);
        ExternalProcessorService service = new ExternalProcessorService(
                new DefaultTurnPipeline(List.of(new OpenAiResponsesAdapter()), engine, repo, metrics,
                        new CoachSessionTracker(), new ReEncodedContentDetector(),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true,
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

    private ProcessingRequest headers(long contentLength) {
        HeaderMap.Builder hm = HeaderMap.newBuilder();
        Map.of(":path", "/v1/responses",
                "user-agent", "codex_cli_rs/1.0",
                "content-length", Long.toString(contentLength))
                .forEach((k, v) -> hm.addHeaders(HeaderValue.newBuilder()
                        .setKey(k).setRawValue(ByteString.copyFromUtf8(v))));
        return ProcessingRequest.newBuilder()
                .setRequestHeaders(HttpHeaders.newBuilder().setHeaders(hm)).build();
    }

    private ProcessingRequest chunk(String content, boolean endOfStream) {
        return ProcessingRequest.newBuilder()
                .setRequestBody(HttpBody.newBuilder()
                        .setBody(ByteString.copyFromUtf8(content)).setEndOfStream(endOfStream)).build();
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

    @Test
    void tailSecretBeyondTheOldPrefixCapIsCaught(@TempDir Path tmp) throws Exception {
        // Three 40 KB chunks (120 KB total, cap 64 KiB): the secret sits in the LAST chunk,
        // far beyond the old buffered prefix — exactly the earlier prefix-only residual gap.
        Harness h = start(tmp.resolve("tail.db"), Action.FLAG, Map.of());
        try {
            String c1 = "{\"model\":\"gpt-5-codex\",\"input\":\"" + "x".repeat(CHUNK);
            String c2 = "y".repeat(CHUNK);
            String c3 = "z".repeat(CHUNK) + " " + AWS_KEY + " \"}";
            long total = c1.length() + c2.length() + c3.length();

            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(total),
                    chunk(c1, false), chunk(c2, false), chunk(c3, true),
                    responseHeaders(), responseBody()));

            assertThat(out).hasSize(6);
            // The header phase switched this Turn to STREAMED full-body inspection.
            assertThat(out.getFirst().getModeOverride().getRequestBodyMode())
                    .isEqualTo(ProcessingMode.BodySendMode.STREAMED);
            // Every chunk flowed (FLAG posture): no mutation, no immediate response.
            for (int i = 1; i <= 3; i++) {
                assertThat(out.get(i).getResponseCase())
                        .isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
            }

            assertThat(h.repo().count()).isEqualTo(1);
            assertThat(h.jdbc().sql("SELECT action FROM turns").query(String.class).single())
                    .isEqualTo("FLAG");
            List<String> rules = h.jdbc().sql("SELECT rule FROM findings ORDER BY rule")
                    .query(String.class).list();
            assertThat(rules).containsExactly("aws-access-token", TurnState.OVERSIZE_RULE);
            // Model attribution still works: peeked from the first streamed chunk.
            assertThat(h.jdbc().sql("SELECT requested_model FROM turns").query(String.class).single())
                    .isEqualTo("gpt-5-codex");
        } finally {
            shutdown(h);
        }
    }

    @Test
    void secretSpanningAChunkBoundaryIsCaughtByTheOverlapWindow(@TempDir Path tmp) throws Exception {
        // The key is split mid-token across two 40 KB chunks; only the carried 4 KiB
        // overlap makes it visible to the scanner.
        Harness h = start(tmp.resolve("span.db"), Action.FLAG, Map.of());
        try {
            String firstHalf = AWS_KEY.substring(0, 12);
            String secondHalf = AWS_KEY.substring(12);
            String c1 = "{\"model\":\"gpt-5-codex\",\"input\":\"" + "x".repeat(CHUNK) + " " + firstHalf;
            String c2 = secondHalf + " " + "y".repeat(CHUNK) + "\"}";
            long total = c1.length() + c2.length();

            exchange(h.channel(), List.of(
                    headers(total),
                    chunk(c1, false), chunk(c2, true),
                    responseHeaders(), responseBody()));

            List<String> rules = h.jdbc().sql("SELECT rule FROM findings ORDER BY rule")
                    .query(String.class).list();
            assertThat(rules).containsExactly("aws-access-token", TurnState.OVERSIZE_RULE);
        } finally {
            shutdown(h);
        }
    }

    @Test
    void blockOnFirstChunkRecordsNoPartialEgress(@TempDir Path tmp) throws Exception {
        // The blocking chunk itself is withheld (Envoy forwards a chunk only after its
        // CONTINUE), so a first-chunk block means zero bytes egressed — no partial-egress.
        Harness h = start(tmp.resolve("first.db"), Action.FLAG, Map.of("aws-access-token", Action.BLOCK));
        try {
            String c1 = "{\"model\":\"gpt-5-codex\",\"input\":\"" + "x".repeat(CHUNK) + " " + AWS_KEY + " ";
            long total = c1.length() + CHUNK;

            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(total),
                    chunk(c1, false)));

            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            List<String> rules = h.jdbc().sql("SELECT rule FROM findings ORDER BY rule")
                    .query(String.class).list();
            assertThat(rules).containsExactly("aws-access-token", TurnState.OVERSIZE_RULE);
        } finally {
            shutdown(h);
        }
    }

    @Test
    void midStreamBlockStopsRemainderAndRecordsPartialEgress(@TempDir Path tmp) throws Exception {
        // aws rule = BLOCK; the secret arrives in chunk 2 of 3. Chunk 1 already egressed,
        // so the blocked Turn must carry partial-egress — never reported as "nothing left".
        Harness h = start(tmp.resolve("block.db"), Action.FLAG, Map.of("aws-access-token", Action.BLOCK));
        try {
            String c1 = "{\"model\":\"gpt-5-codex\",\"input\":\"" + "x".repeat(CHUNK);
            String c2 = "y".repeat(CHUNK) + " " + AWS_KEY + " ";
            String c3 = "z".repeat(CHUNK) + "\"}";
            long total = c1.length() + c2.length() + c3.length();

            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(total),
                    chunk(c1, false), chunk(c2, false)));

            assertThat(out).hasSize(3);
            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
            assertThat(out.get(2).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(out.get(2).getImmediateResponse().getStatus().getCode().getNumber()).isEqualTo(403);

            assertThat(h.repo().count()).isEqualTo(1);
            assertThat(h.jdbc().sql("SELECT action FROM turns").query(String.class).single())
                    .isEqualTo("BLOCK");
            List<String> rules = h.jdbc().sql("SELECT rule FROM findings ORDER BY rule")
                    .query(String.class).list();
            assertThat(rules).containsExactly("aws-access-token", TurnState.OVERSIZE_RULE,
                    TurnState.PARTIAL_EGRESS_RULE);
            assertThat(h.registry().find("hamza.egress.blocked")
                    .tag("rule", "aws-access-token").counter()).isNotNull();
        } finally {
            shutdown(h);
        }
    }
}
