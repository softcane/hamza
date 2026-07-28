package ai.hamza.extproc;

import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.extensions.filters.http.ext_proc.v3.ProcessingMode;
import io.envoyproxy.envoy.service.ext_proc.v3.ExternalProcessorGrpc;
import io.envoyproxy.envoy.service.ext_proc.v3.HttpHeaders;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingRequest;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingResponse;
import io.grpc.stub.StreamObserver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/** Translates Envoy ext_proc messages to and from the plain-Java Turn pipeline. */
@Service
public final class ExternalProcessorService
        extends ExternalProcessorGrpc.ExternalProcessorImplBase {

    private final TurnPipeline pipeline;
    private final CoachResponder coachResponder;

    @Autowired
    public ExternalProcessorService(TurnPipeline pipeline, CoachResponder coachResponder) {
        this.pipeline = java.util.Objects.requireNonNull(pipeline, "pipeline");
        this.coachResponder = coachResponder == null ? CoachResponder.disabled() : coachResponder;
    }

    ExternalProcessorService(TurnPipeline pipeline) {
        this(pipeline, CoachResponder.disabled());
    }

    @Override
    public StreamObserver<ProcessingRequest> process(StreamObserver<ProcessingResponse> out) {
        TurnPipeline.Session session = pipeline.openSession(coachResponder.enabled());
        return new StreamObserver<>() {
            @Override
            public void onNext(ProcessingRequest request) {
                out.onNext(translate(session, request));
            }

            @Override
            public void onError(Throwable failure) {
                try {
                    session.onTransportError(failure);
                } finally {
                    session.close();
                }
            }

            @Override
            public void onCompleted() {
                try {
                    session.onTransportCompleted();
                    out.onCompleted();
                } finally {
                    session.close();
                }
            }
        };
    }

    private ProcessingResponse translate(TurnPipeline.Session session,
                                         ProcessingRequest request) {
        TurnPipeline.Decision decision = switch (request.getRequestCase()) {
            case REQUEST_HEADERS -> session.onRequestHeaders(headers(request.getRequestHeaders()));
            case REQUEST_BODY -> session.onRequestBody(
                    request.getRequestBody().getBody().toByteArray(),
                    request.getRequestBody().getEndOfStream());
            case RESPONSE_HEADERS -> {
                session.onResponseHeaders(status(request.getResponseHeaders()),
                        request.getResponseHeaders().getEndOfStream());
                yield TurnPipeline.Continue.unchanged();
            }
            case RESPONSE_BODY -> {
                session.onResponseBody(request.getResponseBody().getBody().toByteArray(),
                        request.getResponseBody().getEndOfStream());
                yield TurnPipeline.Continue.unchanged();
            }
            case REQUEST_TRAILERS, RESPONSE_TRAILERS, REQUEST_NOT_SET ->
                    TurnPipeline.Continue.unchanged();
        };
        return render(request, decision);
    }

    private ProcessingResponse render(ProcessingRequest request,
                                      TurnPipeline.Decision decision) {
        return switch (decision) {
            case TurnPipeline.Block block ->
                    coachResponder.blockResponse(block.provider(), block.blockingRules());
            case TurnPipeline.Continue continued -> {
                byte[] replacement = continued.replacementBody();
                if (replacement != null) {
                    yield continued.repairManagedFraming()
                            ? ProcessingResponses.replaceManagedRequestBody(replacement)
                            : ProcessingResponses.maskRequestBody(replacement);
                }
                if (request.getRequestCase()
                        != ProcessingRequest.RequestCase.REQUEST_HEADERS) {
                    yield ProcessingResponses.continueFor(request);
                }
                if (!continued.removeHeaders().isEmpty()) {
                    yield ProcessingResponses.continueRequestHeadersWithBodyModeAndRemoveHeaders(
                            bodyMode(continued.bodyMode()), continued.removeHeaders());
                }
                yield switch (continued.bodyMode()) {
                    case NONE -> ProcessingResponses.continueRequestHeadersWithoutRequestBody();
                    case BUFFERED ->
                            ProcessingResponses.continueRequestHeadersWithBufferedRequestBody();
                    case BUFFERED_PARTIAL ->
                            ProcessingResponses.continueRequestHeadersWithPartialRequestBody();
                    case STREAMED ->
                            ProcessingResponses.continueRequestHeadersWithStreamedRequestBody();
                    case UNCHANGED -> ProcessingResponses.continueRequestHeaders();
                };
            }
        };
    }

    private static TurnPipeline.RequestHeaders headers(HttpHeaders headers) {
        RequestHeaderView view = RequestHeaderView.from(headers);
        return new TurnPipeline.RequestHeaders(view.routingHeaders(), view.managedHeaders(),
                view.duplicateRoutingHeaders(), view.routeProvider(), headers.getEndOfStream());
    }

    private static ProcessingMode.BodySendMode bodyMode(TurnPipeline.BodyMode mode) {
        return switch (mode) {
            case NONE -> ProcessingMode.BodySendMode.NONE;
            case BUFFERED -> ProcessingMode.BodySendMode.BUFFERED;
            case BUFFERED_PARTIAL -> ProcessingMode.BodySendMode.BUFFERED_PARTIAL;
            case STREAMED -> ProcessingMode.BodySendMode.STREAMED;
            case UNCHANGED -> ProcessingMode.BodySendMode.NONE;
        };
    }

    private static int status(HttpHeaders headers) {
        for (HeaderValue header : headers.getHeaders().getHeadersList()) {
            if (":status".equalsIgnoreCase(header.getKey())) {
                String value = header.getValue();
                if (value == null || value.isEmpty()) {
                    value = header.getRawValue().toStringUtf8();
                }
                try {
                    return Integer.parseInt(value.trim());
                } catch (NumberFormatException ignored) {
                    return 0;
                }
            }
        }
        return 0;
    }
}
