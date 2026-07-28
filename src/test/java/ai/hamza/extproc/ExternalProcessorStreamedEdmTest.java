package ai.hamza.extproc;

import ai.hamza.adapter.OpenAiResponsesAdapter;
import ai.hamza.config.HamzaProperties;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.edm.RegistryStore;
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

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Turn-level EDM accumulation through the real gRPC service: a customer
 * dump split across streamed chunks — each chunk below the block threshold — must
 * still block once the Turn's running distinct-match total crosses it.
 */
class ExternalProcessorStreamedEdmTest {

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

    private record Harness(Server server, ManagedChannel channel, JdbcClient jdbc) {
    }

    private Harness start(Path db) throws Exception {
        JdbcClient jdbc = jdbcOn(db);
        Path registryDir = Path.of(getClass().getResource("/edm").toURI());
        HamzaProperties props = new HamzaProperties(new HamzaProperties.Metrics(Map.of()),
                new HamzaProperties.Policy(Action.FLAG, Map.of("edm-customers", Action.BLOCK),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true),
                new HamzaProperties.Edm(registryDir.toString(), 10, true, null));
        EdmMatcher matcher = new EdmMatcher(new RegistryStore(props));
        PolicyEngine engine = new PolicyEngine(new SecretDetector(), new Masker(),
                Action.FLAG, Map.of("edm-customers", Action.BLOCK), matcher, 10);
        ExternalProcessorService service = new ExternalProcessorService(
                new DefaultTurnPipeline(List.of(new OpenAiResponsesAdapter()), engine,
                        new TurnRepository(jdbc), new HamzaMetrics(new SimpleMeterRegistry(), props),
                        new CoachSessionTracker(), new ReEncodedContentDetector(),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true,
                        ManagedContinuationRuntime.disabled()));

        String name = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(name).directExecutor().addService(service).build().start();
        ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        return new Harness(server, channel, jdbc);
    }

    @Test
    void dumpSplitAcrossChunksBlocksOnceTurnTotalCrossesThreshold(@TempDir Path tmp) throws Exception {
        Harness h = start(tmp.resolve("edmstream.db"));
        try {
            // Chunk-1 emails sit BEFORE 40KB of filler: far outside the 4KiB overlap
            // carried into chunk 2's window, so only Turn-level accumulation can
            // combine them with chunk 2's emails.
            StringBuilder c1 = new StringBuilder("{\"model\":\"gpt-5-codex\",\"input\":\"");
            for (int i = 1; i <= 6; i++) {
                c1.append(" fake%03d@example-corp.test".formatted(i));
            }
            c1.append("x".repeat(40_000));
            StringBuilder c2 = new StringBuilder();
            for (int i = 7; i <= 12; i++) {
                c2.append(" fake%03d@example-corp.test".formatted(i));
            }
            c2.append("y".repeat(40_000)).append("\"}");
            long total = c1.length() + c2.length();

            List<ProcessingResponse> out = exchange(h.channel(), List.of(
                    headers(total),
                    chunk(c1.toString(), false),
                    chunk(c2.toString(), false)));

            // Chunk 1 (6 distinct) flows; chunk 2 pushes the Turn to 12 → immediate 403.
            assertThat(out.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
            assertThat(out.get(2).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(out.get(2).getImmediateResponse().getStatus().getCode().getNumber()).isEqualTo(403);

            List<String> rules = h.jdbc().sql("SELECT rule || ':' || action FROM findings ORDER BY rule")
                    .query(String.class).list();
            assertThat(rules).contains("edm-customers:BLOCK", TurnState.PARTIAL_EGRESS_RULE + ":BLOCK");
        } finally {
            h.channel().shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
            h.server().shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
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
}
