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
import io.envoyproxy.envoy.config.core.v3.HeaderValueOption;
import io.envoyproxy.envoy.extensions.filters.http.ext_proc.v3.ProcessingMode;
import io.envoyproxy.envoy.service.ext_proc.v3.ExternalProcessorGrpc;
import io.envoyproxy.envoy.service.ext_proc.v3.HttpBody;
import io.envoyproxy.envoy.service.ext_proc.v3.HttpHeaders;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingRequest;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingResponse;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.sqlite.SQLiteDataSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Gate-level (gRPC) policy behaviour: Block returns 403 before Egress, Mask rewrites
 * the body and fixes Content-Length, and the provider Authorization header is never
 * scanned (content-free invariants).
 */
class ExternalProcessorPolicyTest {

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

    private Harness start(Path db, Action posture, Map<String, Action> overrides) throws Exception {
        return start(db, posture, overrides, HamzaProperties.DEFAULT_MAX_BODY_BYTES);
    }

    private Harness start(Path db, Action posture, Map<String, Action> overrides,
                          int maxBodyBytes) throws Exception {
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository repo = new TurnRepository(jdbc);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        HamzaMetrics metrics = new HamzaMetrics(registry,
                new HamzaProperties(new HamzaProperties.Metrics(Map.of()),
                        new HamzaProperties.Policy(posture, overrides, maxBodyBytes,
                                HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, false)));
        PolicyEngine engine = new PolicyEngine(new SecretDetector(), new Masker(), posture, overrides);
        ExternalProcessorService service = new ExternalProcessorService(
                new DefaultTurnPipeline(List.of(new OpenAiResponsesAdapter()), engine, repo, metrics,
                        new CoachSessionTracker(), new ReEncodedContentDetector(), maxBodyBytes,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, false,
                        ManagedContinuationRuntime.disabled()));

        String name = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(name).directExecutor().addService(service).build().start();
        ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        return new Harness(server, channel, repo, registry, jdbc);
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

    private ProcessingRequest body(String content) {
        return body(content, true);
    }

    private ProcessingRequest body(String content, boolean endOfStream) {
        return ProcessingRequest.newBuilder()
                .setRequestBody(HttpBody.newBuilder()
                        .setBody(ByteString.copyFromUtf8(content)).setEndOfStream(endOfStream)).build();
    }

    private ProcessingRequest responseHeaders() {
        return responseHeaders(false);
    }

    private ProcessingRequest responseHeaders(boolean endOfStream) {
        HeaderMap.Builder hm = HeaderMap.newBuilder();
        hm.addHeaders(HeaderValue.newBuilder()
                .setKey(":status").setRawValue(ByteString.copyFromUtf8("200")));
        return ProcessingRequest.newBuilder()
                .setResponseHeaders(HttpHeaders.newBuilder().setHeaders(hm)
                        .setEndOfStream(endOfStream)).build();
    }

    private ProcessingRequest responseBody() {
        return responseBody("gpt-5-codex");
    }

    private ProcessingRequest responseBody(String servedModel) {
        String sse = """
                event: response.completed
                data: {"type":"response.completed","response":{"model":"%s","status":"completed",\
                "usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}

                data: [DONE]
                """.formatted(servedModel);
        return ProcessingRequest.newBuilder()
                .setResponseBody(HttpBody.newBuilder()
                        .setBody(ByteString.copyFromUtf8(sse)).setEndOfStream(true)).build();
    }

    @Test
    void blockReturns403BeforeEgress(@TempDir Path tmp) throws Exception {
        Harness h = start(tmp.resolve("b.db"), Action.FLAG, Map.of("aws-access-token", Action.BLOCK));
        try {
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0")),
                    body("{\"model\":\"gpt-5-codex\",\"input\":\"" + AWS_KEY + "\"}")));

            assertThat(out).hasSize(2);
            assertThat(out.get(0).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_HEADERS);
            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(out.get(1).getImmediateResponse().getStatus().getCode().getNumber()).isEqualTo(403);

            // A content-free blocked Turn is recorded, and the egress-blocked meter fired.
            assertThat(h.repo().count()).isEqualTo(1);
            assertThat(h.registry().find("hamza.egress.blocked").tag("rule", "aws-access-token").counter())
                    .isNotNull();
        } finally {
            shutdown(h);
        }
    }

    @Test
    void maskRewritesBodyAndFixesContentLength(@TempDir Path tmp) throws Exception {
        Harness h = start(tmp.resolve("r.db"), Action.MASK, Map.of());
        try {
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0")),
                    body("{\"model\":\"gpt-5-codex\",\"input\":\"" + AWS_KEY + "\"}")));

            assertThat(out).hasSize(2);
            ProcessingResponse bodyResp = out.get(1);
            assertThat(bodyResp.getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);

            var common = bodyResp.getRequestBody().getResponse();
            byte[] newBody = common.getBodyMutation().getBody().toByteArray();
            String newText = new String(newBody, StandardCharsets.UTF_8);
            assertThat(newText).doesNotContain(AWS_KEY);
            assertThat(newText).containsPattern("<SECRET_\\d+>");

            // Content-Length is overwritten to match the new body (framing invariant).
            String contentLength = common.getHeaderMutation().getSetHeadersList().stream()
                    .map(HeaderValueOption::getHeader)
                    .filter(hv -> hv.getKey().equalsIgnoreCase("content-length"))
                    .map(hv -> hv.getRawValue().toStringUtf8())
                    .findFirst().orElse(null);
            assertThat(contentLength).isEqualTo(Integer.toString(newBody.length));
        } finally {
            shutdown(h);
        }
    }

    @Test
    void authorizationHeaderIsNeverScannedOrBlocked(@TempDir Path tmp) throws Exception {
        // A secret-shaped value lives ONLY in the Authorization header; the body is clean.
        Harness h = start(tmp.resolve("a.db"), Action.FLAG, Map.of("aws-access-token", Action.BLOCK));
        try {
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "authorization", "Bearer " + AWS_KEY)),
                    body("{\"model\":\"gpt-5-codex\",\"input\":\"hello\"}")));

            // No block, no masking: the auth header was never inspected.
            assertThat(out).hasSize(2);
            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
            assertThat(out.get(1).getRequestBody().getResponse().getStatus().getNumber()).isZero(); // CONTINUE
            assertThat(h.registry().find("hamza.egress.blocked").counter()).isNull();
        } finally {
            shutdown(h);
        }
    }

    @Test
    void trustedRouteHintRecordsZeroBodyProviderRequestAtHeaderEndOfStream(@TempDir Path tmp)
            throws Exception {
        Harness h = start(tmp.resolve("head.db"), Action.FLAG, Map.of());
        try {
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/", "content-length", "0",
                            "x-request-id", "head-probe-1",
                            RequestHeaderView.ROUTE_PROVIDER_HEADER, "openai")),
                    responseHeaders(true)));

            assertThat(out).hasSize(2);
            assertThat(h.repo().count()).isEqualTo(1);
            assertThat(h.jdbc().sql("""
                    select request_id || ':' || provider || ':' || action || ':'
                         || request_bytes_egressed from turns
                    """).query(String.class).single())
                    .isEqualTo("head-probe-1:openai:FLAG:0");
        } finally {
            shutdown(h);
        }
    }

    @Test
    void trustedRouteHintDoesNotRecordLocalReadyResponse(@TempDir Path tmp) throws Exception {
        Harness h = start(tmp.resolve("ready.db"), Action.FLAG, Map.of());
        try {
            exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/ready", "content-length", "0",
                            "x-request-id", "ready-1",
                            RequestHeaderView.ROUTE_PROVIDER_HEADER, "openai")),
                    responseHeaders(true)));

            assertThat(h.repo().count()).isZero();
        } finally {
            shutdown(h);
        }
    }

    @Test
    void oversizedBodyInspectsPrefixFlagsLeadingSecretAndRecordsOversize(@TempDir Path tmp) throws Exception {
        // Oversize (cap = 32): the tail is uninspected, but the buffered prefix is still
        // scanned so a leading secret is caught. A partial body cannot be masked, so the
        // secret is FLAG-only (not MASK) and the Turn stays FLAG — never a body mutation.
        Harness h = start(tmp.resolve("o.db"), Action.MASK, Map.of(), 32);
        try {
            String oversizeBody = "{\"model\":\"gpt-5-codex\",\"input\":\"" + AWS_KEY + " " + "x".repeat(128) + "\"}";
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "content-length", Integer.toString(oversizeBody.length()))),
                    body(oversizeBody, false),
                    responseHeaders(),
                    responseBody()));

            assertThat(out).hasSize(4);
            // The header phase asks Envoy for the bounded prefix, not the whole body.
            assertThat(out.getFirst().getModeOverride().getRequestBodyMode())
                    .isEqualTo(ProcessingMode.BodySendMode.BUFFERED_PARTIAL);
            // The body is flagged, never mutated (cannot mask a partial body) and not blocked.
            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
            assertThat(out.get(1).getRequestBody().getResponse().getStatus().getNumber()).isZero();
            assertThat(out.get(1).getRequestBody().getResponse().hasBodyMutation()).isFalse();

            assertThat(h.repo().count()).isEqualTo(1);
            assertThat(h.jdbc().sql("SELECT action FROM turns").query(String.class).single())
                    .isEqualTo("FLAG");
            // Both the leading secret (FLAG-only, downgraded from MASK) and the oversize marker.
            List<String> rules = h.jdbc().sql("SELECT rule FROM findings ORDER BY rule").query(String.class).list();
            assertThat(rules).containsExactly("aws-access-token", TurnState.OVERSIZE_RULE);
            assertThat(h.registry().find("hamza.policy.violations")
                    .tag("rule", "aws-access-token").tag("action", "FLAG").counter()).isNotNull();
            assertThat(h.registry().find("hamza.policy.violations")
                    .tag("rule", TurnState.OVERSIZE_RULE).tag("action", "FLAG").counter()).isNotNull();
            // Model is still attributed from the prefix (P2): requested_model is not null.
            assertThat(h.jdbc().sql("SELECT requested_model FROM turns").query(String.class).single())
                    .isEqualTo("gpt-5-codex");
        } finally {
            shutdown(h);
        }
    }

    @Test
    void oversizedBodyWithLeadingSecretBlocksWhenRuleBlocks(@TempDir Path tmp) throws Exception {
        // FLAG posture, but the aws rule is BLOCK: a secret in the buffered prefix of an
        // oversize body still blocks before Egress (block wins even on a partial body).
        Harness h = start(tmp.resolve("obs.db"), Action.FLAG, Map.of("aws-access-token", Action.BLOCK), 32);
        try {
            String oversizeBody = "{\"model\":\"gpt-5-codex\",\"input\":\"" + AWS_KEY + " " + "x".repeat(128) + "\"}";
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "content-length", Integer.toString(oversizeBody.length()))),
                    body(oversizeBody, false)));

            assertThat(out).hasSize(2);
            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(out.get(1).getImmediateResponse().getStatus().getCode().getNumber()).isEqualTo(403);
            assertThat(h.registry().find("hamza.egress.blocked")
                    .tag("rule", "aws-access-token").counter()).isNotNull();
        } finally {
            shutdown(h);
        }
    }

    @Test
    void oversizedBodyStillEmitsModelFallbackMetric(@TempDir Path tmp) throws Exception {
        // P2 regression: requested_model is peeked from the oversize prefix, so a served
        // model change is still visible to the fallback metric.
        Harness h = start(tmp.resolve("fallback.db"), Action.FLAG, Map.of(), 32);
        try {
            String oversizeBody = "{\"model\":\"gpt-5-codex\",\"input\":\"" + "x".repeat(128) + "\"}";
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "content-length", Integer.toString(oversizeBody.length()))),
                    body(oversizeBody, false),
                    responseHeaders(),
                    responseBody("gpt-5-mini")));

            assertThat(out).hasSize(4);
            assertThat(h.jdbc().sql("SELECT requested_model || '->' || served_model FROM turns")
                    .query(String.class).single()).isEqualTo("gpt-5-codex->gpt-5-mini");
            assertThat(h.registry().find("hamza.model.fallback")
                    .tag("requested", "gpt-5-codex").tag("served", "gpt-5-mini").counter())
                    .isNotNull();
        } finally {
            shutdown(h);
        }
    }

    @Test
    void oversizedBodyBlocksInBlockPosture(@TempDir Path tmp) throws Exception {
        Harness h = start(tmp.resolve("ob.db"), Action.BLOCK, Map.of(), 32);
        try {
            String oversizeBody = "{\"model\":\"gpt-5-codex\",\"input\":\"" + AWS_KEY + " " + "x".repeat(128) + "\"}";
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "content-length", Integer.toString(oversizeBody.length())))));

            assertThat(out).hasSize(1);
            assertThat(out.getFirst().getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(out.getFirst().getImmediateResponse().getStatus().getCode().getNumber()).isEqualTo(403);

            assertThat(h.repo().count()).isEqualTo(1);
            assertThat(h.jdbc().sql("SELECT action FROM turns").query(String.class).single())
                    .isEqualTo("BLOCK");
            assertThat(h.jdbc().sql("SELECT rule || ':' || action FROM findings").query(String.class).list())
                    .containsExactly(TurnState.OVERSIZE_RULE + ":BLOCK");
            assertThat(h.registry().find("hamza.egress.blocked")
                    .tag("rule", TurnState.OVERSIZE_RULE).counter()).isNotNull();
        } finally {
            shutdown(h);
        }
    }

    @Test
    void controlPlanePathRequestsNoBodyAndRecordsOversize(@TempDir Path tmp) throws Exception {
        Harness h = start(tmp.resolve("c.db"), Action.MASK, Map.of(), 32);
        try {
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/backend-api/codex/responses/compact",
                            "user-agent", "codex_cli_rs/1.0")),
                    responseHeaders(),
                    responseBody()));

            assertThat(out).hasSize(3);
            ProcessingResponse headerResponse = out.getFirst();
            assertThat(headerResponse.getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_HEADERS);
            assertThat(headerResponse.hasModeOverride()).isTrue();
            assertThat(headerResponse.getModeOverride().getRequestBodyMode())
                    .isEqualTo(ProcessingMode.BodySendMode.NONE);

            assertThat(h.repo().count()).isEqualTo(1);
            assertThat(h.jdbc().sql("SELECT rule FROM findings").query(String.class).list())
                    .containsExactly(TurnState.OVERSIZE_RULE);
        } finally {
            shutdown(h);
        }
    }

    @Test
    void knownBodyBytesReportsTheObservedLengthWhenContentLengthIsUnknownAndTheStreamEnds(
            @TempDir Path tmp) throws Exception {
        // knownBodyBytes (DefaultTurnPipelineSession:824-830): with no declared
        // content-length, requestContentLength() stays 0 (never >= observedBytes), so the
        // ternary's own branch decides the recorded byte count. At end-of-stream it must
        // report what was actually observed rather than leaving it unknown.
        Harness h = start(tmp.resolve("known-body-bytes-eos.db"), Action.FLAG, Map.of(), 32);
        try {
            String oversizeBody = "x".repeat(64);
            exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0")),
                    body(oversizeBody, true), responseHeaders(), responseBody()));

            assertThat(h.jdbc().sql("SELECT request_bytes_received FROM turns")
                    .query(Long.class).single()).isEqualTo((long) oversizeBody.length());
        } finally {
            shutdown(h);
        }
    }

    // knownBodyBytes's other branch (line 829, `endOfStream ? (long) observedBytes : null`)
    // returns null exactly when a non-blocking oversize prefix has an unknown declared
    // length and the stream has not ended. That value flows straight into
    // `state.setRequestByteCounts(knownBodyBytes, ..., block ? 0L : knownBodyBytes)`
    // (DefaultTurnPipelineSession:286): with block == false the ternary's `Long`/`long`
    // mix auto-unboxes `knownBodyBytes`, so a genuine request matching this shape throws
    // an uncaught NullPointerException out of onRequestBody (confirmed by attempting this
    // exact test: gRPC logs "SEVERE: Exception while executing runnable ... NPE: Cannot
    // invoke Long.longValue() because knownBodyBytes is null" and the call errors instead
    // of completing). This is a pre-existing production defect, not a refactor regression;
    // R1 is test-only (no src/main/java changes are in scope), so it is reported here
    // rather than fixed, and this branch is left uncharacterized: a test that reaches it
    // cannot assert graceful behavior because none currently exists.

    private void shutdown(Harness h) throws Exception {
        h.channel().shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        h.server().shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }
}
