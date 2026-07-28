package ai.hamza.extproc;

import ai.hamza.adapter.OpenAiResponsesAdapter;
import ai.hamza.config.HamzaProperties;
import ai.hamza.metrics.HamzaMetrics;
import ai.hamza.persistence.TurnRepository;
import ai.hamza.policy.Action;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.Masker;
import ai.hamza.policy.SecretDetector;
import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Gate-level Coach behaviour: a Block presents as a Provider-shaped body
 * naming the rule class only; the bare-403 fallback holds when Coach is off; and an
 * evasive re-encode after a coach in the same session escalates to a hard Block. Coach
 * never changes WHAT is blocked — only how the Block is presented (ordering invariant).
 */
class ExternalProcessorCoachTest {

    private static final String AWS_KEY = "AKIAABCDEFGHIJKLMNOP";
    private static final ObjectMapper MAPPER = new ObjectMapper();

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

    private record Harness(Server server, ManagedChannel channel, TurnRepository repo, JdbcClient jdbc) {
    }

    private Harness start(Path db, Action posture, Map<String, Action> overrides,
                          CoachResponder coach) throws Exception {
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository repo = new TurnRepository(jdbc);
        HamzaMetrics metrics = new HamzaMetrics(new SimpleMeterRegistry(),
                new HamzaProperties(new HamzaProperties.Metrics(Map.of()),
                        new HamzaProperties.Policy(posture, overrides,
                                HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                                HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, false)));
        PolicyEngine engine = new PolicyEngine(new SecretDetector(), new Masker(), posture, overrides);
        CoachSessionTracker sessions = new CoachSessionTracker();
        ExternalProcessorService service = new ExternalProcessorService(
                new DefaultTurnPipeline(List.of(new OpenAiResponsesAdapter()), engine, repo, metrics,
                        sessions, new ReEncodedContentDetector(),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, false,
                        ManagedContinuationRuntime.disabled()),
                coach);

        String name = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(name).directExecutor().addService(service).build().start();
        ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        return new Harness(server, channel, repo, jdbc);
    }

    private Harness startStreamed(Path db, Action posture, Map<String, Action> overrides,
                                  int maxBodyBytes, CoachResponder coach) throws Exception {
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository repo = new TurnRepository(jdbc);
        HamzaMetrics metrics = new HamzaMetrics(new SimpleMeterRegistry(),
                new HamzaProperties(new HamzaProperties.Metrics(Map.of()),
                        new HamzaProperties.Policy(posture, overrides, maxBodyBytes,
                                HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true)));
        PolicyEngine engine = new PolicyEngine(new SecretDetector(), new Masker(), posture, overrides);
        CoachSessionTracker sessions = new CoachSessionTracker();
        ExternalProcessorService service = new ExternalProcessorService(
                new DefaultTurnPipeline(List.of(new OpenAiResponsesAdapter()), engine, repo, metrics,
                        sessions, new ReEncodedContentDetector(), maxBodyBytes,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true,
                        ManagedContinuationRuntime.disabled()),
                coach);
        String name = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(name).directExecutor().addService(service).build().start();
        ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        return new Harness(server, channel, repo, jdbc);
    }

    private ProcessingRequest headersCl(long contentLength, String session) {
        HeaderMap.Builder hm = HeaderMap.newBuilder();
        Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                        "content-length", Long.toString(contentLength), "session_id", session)
                .forEach((k, v) -> hm.addHeaders(HeaderValue.newBuilder()
                        .setKey(k).setRawValue(ByteString.copyFromUtf8(v))));
        return ProcessingRequest.newBuilder()
                .setRequestHeaders(HttpHeaders.newBuilder().setHeaders(hm)).build();
    }

    private ProcessingRequest bodyChunk(String content, boolean endOfStream) {
        return ProcessingRequest.newBuilder()
                .setRequestBody(HttpBody.newBuilder()
                        .setBody(ByteString.copyFromUtf8(content)).setEndOfStream(endOfStream)).build();
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
        return ProcessingRequest.newBuilder()
                .setRequestBody(HttpBody.newBuilder()
                        .setBody(ByteString.copyFromUtf8(content)).setEndOfStream(true)).build();
    }

    private String immediateBody(ProcessingResponse resp) {
        return resp.getImmediateResponse().getBody().toStringUtf8();
    }

    @Test
    void blockPresentsProviderShapedCoachBodyNamingRuleClassOnly(@TempDir Path tmp) throws Exception {
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        Harness h = start(tmp.resolve("coach.db"), Action.FLAG, Map.of("aws-access-token", Action.BLOCK), coach);
        try {
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0")),
                    body("{\"model\":\"gpt-5-codex\",\"input\":\"" + AWS_KEY + "\"}")));

            ProcessingResponse blk = out.get(1);
            assertThat(blk.getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(blk.getImmediateResponse().getStatus().getCode().getNumber()).isEqualTo(403);
            String bodyText = immediateBody(blk);
            // Valid OpenAI-error wire shape, names the rule class, leaks zero matched content.
            assertThat(MAPPER.readTree(bodyText).path("error").path("message").asText())
                    .contains("aws-access-token");
            assertThat(bodyText).doesNotContain(AWS_KEY);
            // WHAT is blocked is unchanged: a content-free BLOCK Turn is still recorded.
            assertThat(h.repo().count()).isEqualTo(1);
            assertThat(h.jdbc().sql("SELECT action FROM turns").query(String.class).single()).isEqualTo("BLOCK");
        } finally {
            shutdown(h);
        }
    }

    @Test
    void bareFallbackWhenCoachDisabled(@TempDir Path tmp) throws Exception {
        Harness h = start(tmp.resolve("bare.db"), Action.FLAG,
                Map.of("aws-access-token", Action.BLOCK), CoachResponder.disabled());
        try {
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0")),
                    body("{\"model\":\"gpt-5-codex\",\"input\":\"" + AWS_KEY + "\"}")));
            assertThat(immediateBody(out.get(1))).isEqualTo("Blocked by Hamza: aws-access-token\n");
        } finally {
            shutdown(h);
        }
    }

    @Test
    void evasiveReEncodeAfterCoachEscalatesToBlock(@TempDir Path tmp) throws Exception {
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        // FLAG posture: nothing is blocked by policy except the seeded secret block that
        // "coaches" the session, so the second block can ONLY be the evasion escalation.
        Harness h = start(tmp.resolve("evade.db"), Action.FLAG,
                Map.of("aws-access-token", Action.BLOCK), coach);
        try {
            // Turn 1 (session s1): a Block coaches the session.
            exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "session_id", "s1")),
                    body("{\"model\":\"gpt-5-codex\",\"input\":\"" + AWS_KEY + "\"}")));

            // Turn 2 (session s1): a re-encoded high-entropy blob, no secret — must escalate.
            byte[] random = new byte[192];
            for (int i = 0; i < random.length; i++) {
                random[i] = (byte) ((i * 197 + 31) ^ (i << 3));
            }
            String blob = Base64.getEncoder().encodeToString(random);
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "session_id", "s1")),
                    body("{\"model\":\"gpt-5-codex\",\"input\":\"" + blob + "\"}")));

            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(out.get(1).getImmediateResponse().getStatus().getCode().getNumber()).isEqualTo(403);
            // The second Turn is recorded BLOCK with the evasion-suspected Finding (content-free).
            List<String> rules = h.jdbc().sql(
                    "SELECT rule FROM findings WHERE turn_id = (SELECT turn_id FROM turns ORDER BY ts DESC LIMIT 1)")
                    .query(String.class).list();
            assertThat(rules).contains(TurnState.EVASION_RULE);
        } finally {
            shutdown(h);
        }
    }

    @Test
    void reEncodeInUncoachedSessionDoesNotBlock(@TempDir Path tmp) throws Exception {
        // Same re-encoded blob, but the session was never coached: escalation must not fire
        // (Coach changes only the Block's presentation; it never invents a new Block).
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        Harness h = start(tmp.resolve("fresh.db"), Action.FLAG, Map.of(), coach);
        try {
            byte[] random = new byte[192];
            for (int i = 0; i < random.length; i++) {
                random[i] = (byte) ((i * 197 + 31) ^ (i << 3));
            }
            String blob = Base64.getEncoder().encodeToString(random);
            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(Map.of(":path", "/v1/responses", "user-agent", "codex_cli_rs/1.0",
                            "session_id", "fresh")),
                    body("{\"model\":\"gpt-5-codex\",\"input\":\"" + blob + "\"}")));
            // CONTINUE, not blocked.
            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
            assertThat(out.get(1).getRequestBody().getResponse().getStatus().getNumber()).isZero();
        } finally {
            shutdown(h);
        }
    }

    @Test
    void evasiveReEncodeOnStreamedPathEscalates(@TempDir Path tmp) throws Exception {
        // Small cap + streaming on: an over-cap body is scanned chunk by chunk (the streamed
        // path). A coached session that re-encodes its payload into an OVERSIZE body must
        // still be hard-Blocked there, not only on the small-body path.
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        Harness h = startStreamed(tmp.resolve("stream-evade.db"), Action.FLAG,
                Map.of("aws-access-token", Action.BLOCK), 64, coach);
        try {
            // Turn 1 (session s1): an over-cap body carrying a secret streams in and Blocks,
            // coaching the session.
            String seed = "{\"model\":\"gpt-5-codex\",\"input\":\"" + AWS_KEY + " "
                    + "x".repeat(128) + "\"}";
            exchange(h.channel(), List.of(headersCl(seed.length(), "s1"), bodyChunk(seed, true)));

            // Turn 2 (session s1): an over-cap re-encoded blob, no secret — streamed evasion.
            byte[] random = new byte[256];
            for (int i = 0; i < random.length; i++) {
                random[i] = (byte) ((i * 197 + 31) ^ (i << 3));
            }
            String blob = Base64.getEncoder().encodeToString(random);
            String reencoded = "{\"model\":\"gpt-5-codex\",\"input\":\"" + blob + "\"}";
            List<ProcessingResponse> out = exchange(h.channel(),
                    List.of(headersCl(reencoded.length(), "s1"), bodyChunk(reencoded, true)));

            assertThat(out).anyMatch(r ->
                    r.getResponseCase() == ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE
                            && r.getImmediateResponse().getStatus().getCode().getNumber() == 403);
            List<String> rules = h.jdbc().sql(
                    "SELECT rule FROM findings WHERE turn_id = (SELECT turn_id FROM turns ORDER BY ts DESC LIMIT 1)")
                    .query(String.class).list();
            assertThat(rules).contains(TurnState.EVASION_RULE);
        } finally {
            shutdown(h);
        }
    }

    private void shutdown(Harness h) throws Exception {
        h.channel().shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        h.server().shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }
}
