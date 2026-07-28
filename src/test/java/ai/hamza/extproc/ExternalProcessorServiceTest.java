package ai.hamza.extproc;

import io.envoyproxy.envoy.config.core.v3.HeaderMap;
import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.service.ext_proc.v3.ExternalProcessorGrpc;
import io.envoyproxy.envoy.service.ext_proc.v3.HttpHeaders;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingRequest;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingResponse;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * M0 exit condition: a call to {@code process} over an in-process channel returns
 * {@code CONTINUE} for a request-headers message. This also proves the controlplane:api
 * ext_proc stubs link and run against the pinned grpc/protobuf line (the M0 risk).
 */
class ExternalProcessorServiceTest {

    private Server server;
    private ManagedChannel channel;

    @BeforeEach
    void setUp() throws Exception {
        String name = InProcessServerBuilder.generateName();
        server = InProcessServerBuilder.forName(name)
                .directExecutor()
                // No adapters: these tests assert CONTINUE semantics; with no Provider
                // match, finalize short-circuits before persistence, so the repository
                // is never touched. A real PolicyEngine over an empty/clean body is a no-op.
                .addService(new ExternalProcessorService(
                        new DefaultTurnPipeline(java.util.List.of(),
                                new ai.hamza.policy.PolicyEngine(
                                        new ai.hamza.policy.SecretDetector(),
                                        new ai.hamza.policy.Masker(),
                                        ai.hamza.policy.Action.FLAG, java.util.Map.of()),
                                null, null, new CoachSessionTracker(),
                                new ReEncodedContentDetector(),
                                ai.hamza.config.HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                                ai.hamza.config.HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS,
                                false, ManagedContinuationRuntime.disabled())))
                .build()
                .start();
        channel = InProcessChannelBuilder.forName(name).directExecutor().build();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (channel != null) {
            channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
        if (server != null) {
            server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    @Test
    void returnsContinueForRequestHeaders() throws Exception {
        ExternalProcessorGrpc.ExternalProcessorStub stub = ExternalProcessorGrpc.newStub(channel);

        List<ProcessingResponse> responses = new ArrayList<>();
        CountDownLatch done = new CountDownLatch(1);

        StreamObserver<ProcessingRequest> requests = stub.process(new StreamObserver<>() {
            @Override
            public void onNext(ProcessingResponse value) {
                responses.add(value);
            }

            @Override
            public void onError(Throwable t) {
                done.countDown();
            }

            @Override
            public void onCompleted() {
                done.countDown();
            }
        });

        ProcessingRequest headers = ProcessingRequest.newBuilder()
                .setRequestHeaders(HttpHeaders.newBuilder()
                        .setHeaders(HeaderMap.newBuilder()
                                .addHeaders(HeaderValue.newBuilder().setKey(":path").setRawValue(
                                        com.google.protobuf.ByteString.copyFromUtf8("/v1/responses")))
                                .addHeaders(HeaderValue.newBuilder().setKey(":authority").setRawValue(
                                        com.google.protobuf.ByteString.copyFromUtf8("api.openai.com")))))
                .build();

        requests.onNext(headers);
        requests.onCompleted();

        assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(responses).hasSize(1);
        ProcessingResponse response = responses.getFirst();
        // CONTINUE for a request-headers phase == the request_headers response oneof set,
        // with the default (CONTINUE) common-response status.
        assertThat(response.getResponseCase())
                .isEqualTo(ProcessingResponse.ResponseCase.REQUEST_HEADERS);
        assertThat(response.getRequestHeaders().getResponse().getStatus().getNumber()).isZero();
    }

    @Test
    void answersContinueForAllFourPhasesWithMatchingOneof() throws Exception {
        ExternalProcessorGrpc.ExternalProcessorStub stub = ExternalProcessorGrpc.newStub(channel);

        List<ProcessingResponse> responses = new ArrayList<>();
        CountDownLatch done = new CountDownLatch(1);

        StreamObserver<ProcessingRequest> requests = stub.process(new StreamObserver<>() {
            @Override
            public void onNext(ProcessingResponse value) {
                responses.add(value);
            }

            @Override
            public void onError(Throwable t) {
                done.countDown();
            }

            @Override
            public void onCompleted() {
                done.countDown();
            }
        });

        // The four phases Envoy streams for one Turn (request lifecycle).
        requests.onNext(ProcessingRequest.newBuilder()
                .setRequestHeaders(HttpHeaders.getDefaultInstance()).build());
        requests.onNext(ProcessingRequest.newBuilder()
                .setRequestBody(io.envoyproxy.envoy.service.ext_proc.v3.HttpBody.newBuilder()
                        .setBody(com.google.protobuf.ByteString.copyFromUtf8("{\"model\":\"gpt-5-codex\"}"))
                        .setEndOfStream(true)).build());
        requests.onNext(ProcessingRequest.newBuilder()
                .setResponseHeaders(HttpHeaders.getDefaultInstance()).build());
        requests.onNext(ProcessingRequest.newBuilder()
                .setResponseBody(io.envoyproxy.envoy.service.ext_proc.v3.HttpBody.newBuilder()
                        .setEndOfStream(true)).build());
        requests.onCompleted();

        assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        assertThat(responses).hasSize(4);
        // Each response's oneof must match its request phase, all CONTINUE.
        assertThat(responses.get(0).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_HEADERS);
        assertThat(responses.get(1).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
        assertThat(responses.get(2).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.RESPONSE_HEADERS);
        assertThat(responses.get(3).getResponseCase()).isEqualTo(ProcessingResponse.ResponseCase.RESPONSE_BODY);
    }
}
