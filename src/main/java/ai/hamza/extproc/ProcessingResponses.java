package ai.hamza.extproc;

import com.google.protobuf.ByteString;
import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.config.core.v3.HeaderValueOption;
import io.envoyproxy.envoy.extensions.filters.http.ext_proc.v3.ProcessingMode;
import io.envoyproxy.envoy.service.ext_proc.v3.BodyMutation;
import io.envoyproxy.envoy.service.ext_proc.v3.BodyResponse;
import io.envoyproxy.envoy.service.ext_proc.v3.CommonResponse;
import io.envoyproxy.envoy.service.ext_proc.v3.HeaderMutation;
import io.envoyproxy.envoy.service.ext_proc.v3.HeadersResponse;
import io.envoyproxy.envoy.service.ext_proc.v3.ImmediateResponse;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingRequest;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingResponse;
import io.envoyproxy.envoy.service.ext_proc.v3.TrailersResponse;
import io.envoyproxy.envoy.type.v3.HttpStatus;
import io.envoyproxy.envoy.type.v3.StatusCode;

import java.nio.charset.StandardCharsets;
import java.util.Collection;

/**
 * Helpers that build {@link ProcessingResponse}s for the ext_proc contract.
 *
 * <p>Envoy requires a response whose {@code response} oneof matches the
 * {@code request} oneof of the incoming {@link ProcessingRequest}. An empty
 * {@code HeadersResponse}/{@code BodyResponse} means {@code CONTINUE} with no
 * mutation. Mutation and immediate-response (block) helpers arrive with the policy
 * engine in M4.
 */
public final class ProcessingResponses {

    private ProcessingResponses() {
    }

    /** A matching {@code CONTINUE} (no mutation) for whatever phase {@code request} is. */
    public static ProcessingResponse continueFor(ProcessingRequest request) {
        return switch (request.getRequestCase()) {
            case REQUEST_HEADERS ->
                    ProcessingResponse.newBuilder().setRequestHeaders(HeadersResponse.getDefaultInstance()).build();
            case RESPONSE_HEADERS ->
                    ProcessingResponse.newBuilder().setResponseHeaders(HeadersResponse.getDefaultInstance()).build();
            case REQUEST_BODY ->
                    ProcessingResponse.newBuilder().setRequestBody(BodyResponse.getDefaultInstance()).build();
            case RESPONSE_BODY ->
                    ProcessingResponse.newBuilder().setResponseBody(BodyResponse.getDefaultInstance()).build();
            case REQUEST_TRAILERS ->
                    ProcessingResponse.newBuilder().setRequestTrailers(TrailersResponse.getDefaultInstance()).build();
            case RESPONSE_TRAILERS ->
                    ProcessingResponse.newBuilder().setResponseTrailers(TrailersResponse.getDefaultInstance()).build();
            case REQUEST_NOT_SET ->
                    // Nothing actionable; reply with a header CONTINUE so the stream proceeds.
                    ProcessingResponse.newBuilder().setRequestHeaders(HeadersResponse.getDefaultInstance()).build();
        };
    }

    /** A request-headers {@code CONTINUE} with no mutation or mode override. */
    public static ProcessingResponse continueRequestHeaders() {
        return ProcessingResponse.newBuilder()
                .setRequestHeaders(HeadersResponse.getDefaultInstance())
                .build();
    }

    /**
     * Continue after request headers, but tell Envoy not to send the request body to
     * ext_proc for this Turn. Response phases remain enabled so the Turn can still be
     * counted and recorded.
     */
    public static ProcessingResponse continueRequestHeadersWithoutRequestBody() {
        return continueRequestHeadersWithRequestBodyMode(ProcessingMode.BodySendMode.NONE);
    }

    /**
     * Continue after request headers and ask Envoy to buffer the request body. Use this
     * only when headers prove the body is within the inspection cap.
     */
    public static ProcessingResponse continueRequestHeadersWithBufferedRequestBody() {
        return continueRequestHeadersWithRequestBodyMode(ProcessingMode.BodySendMode.BUFFERED);
    }

    public static ProcessingResponse continueRequestHeadersWithBodyModeAndRemoveHeaders(
            ProcessingMode.BodySendMode bodyMode, Collection<String> internalHeaders) {
        HeaderMutation.Builder mutation = HeaderMutation.newBuilder();
        if (internalHeaders != null) {
            internalHeaders.forEach(mutation::addRemoveHeaders);
        }
        CommonResponse common = CommonResponse.newBuilder()
                .setStatus(CommonResponse.ResponseStatus.CONTINUE)
                .setHeaderMutation(mutation)
                .build();
        ProcessingMode processingMode = ProcessingMode.newBuilder()
                .setRequestHeaderMode(ProcessingMode.HeaderSendMode.SEND)
                .setRequestBodyMode(bodyMode)
                .setResponseHeaderMode(ProcessingMode.HeaderSendMode.SEND)
                .setResponseBodyMode(ProcessingMode.BodySendMode.STREAMED)
                .build();
        return ProcessingResponse.newBuilder()
                .setRequestHeaders(HeadersResponse.newBuilder().setResponse(common))
                .setModeOverride(processingMode)
                .build();
    }

    /**
     * Continue after request headers and ask Envoy to <em>stream</em> the request body to
     * ext_proc chunk by chunk (M7 spike: full-body inspection of oversize Turns). Each
     * chunk is forwarded upstream once its CONTINUE is returned, so by the time a later
     * chunk matches, earlier chunks have already egressed — a mid-stream Block stops only
     * the remainder and must be recorded as partial egress.
     */
    public static ProcessingResponse continueRequestHeadersWithStreamedRequestBody() {
        return continueRequestHeadersWithRequestBodyMode(ProcessingMode.BodySendMode.STREAMED);
    }

    /**
     * Continue after request headers and ask Envoy for the <em>partial</em> (prefix-only)
     * request body. Use this for oversized bodies: {@code BUFFERED_PARTIAL} plus the route's
     * {@code per_request_buffer_limit_bytes} bound the buffered prefix to the inspection cap
     * (never a local 413), so the prefix can be scanned while the tail streams through
     * uninspected.
     */
    public static ProcessingResponse continueRequestHeadersWithPartialRequestBody() {
        return continueRequestHeadersWithRequestBodyMode(ProcessingMode.BodySendMode.BUFFERED_PARTIAL);
    }

    private static ProcessingResponse continueRequestHeadersWithRequestBodyMode(
            ProcessingMode.BodySendMode requestBodyMode) {
        ProcessingMode processingMode = ProcessingMode.newBuilder()
                .setRequestHeaderMode(ProcessingMode.HeaderSendMode.SEND)
                .setRequestBodyMode(requestBodyMode)
                .setResponseHeaderMode(ProcessingMode.HeaderSendMode.SEND)
                .setResponseBodyMode(ProcessingMode.BodySendMode.STREAMED)
                .build();
        return ProcessingResponse.newBuilder()
                .setRequestHeaders(HeadersResponse.getDefaultInstance())
                .setModeOverride(processingMode)
                .build();
    }

    /**
     * Replace the outbound request body with {@code newBody} (Mask). Fixes framing by
     * overwriting {@code Content-Length} so length and body agree (content-free invariant).
     */
    public static ProcessingResponse maskRequestBody(byte[] newBody) {
        return replaceRequestBody(newBody, false);
    }

    /** Replace a quarantined source body with its separately rescanned derived body. */
    public static ProcessingResponse replaceManagedRequestBody(byte[] newBody) {
        return replaceRequestBody(newBody, true);
    }

    private static ProcessingResponse replaceRequestBody(byte[] newBody,
                                                         boolean repairManagedFraming) {
        HeaderValueOption contentLength = HeaderValueOption.newBuilder()
                .setHeader(HeaderValue.newBuilder()
                        .setKey("content-length")
                        .setRawValue(ByteString.copyFromUtf8(Integer.toString(newBody.length))))
                .setAppendAction(HeaderValueOption.HeaderAppendAction.OVERWRITE_IF_EXISTS_OR_ADD)
                .build();

        HeaderMutation.Builder headerMutation = HeaderMutation.newBuilder()
                .addSetHeaders(contentLength);
        if (repairManagedFraming) {
            headerMutation.addRemoveHeaders("transfer-encoding");
            headerMutation.addRemoveHeaders("content-encoding");
        }
        CommonResponse common = CommonResponse.newBuilder()
                .setStatus(CommonResponse.ResponseStatus.CONTINUE_AND_REPLACE)
                .setHeaderMutation(headerMutation)
                .setBodyMutation(BodyMutation.newBuilder().setBody(ByteString.copyFrom(newBody)))
                .build();

        return ProcessingResponse.newBuilder()
                .setRequestBody(BodyResponse.newBuilder().setResponse(common))
                .build();
    }

    /** Block the Egress with an immediate HTTP response (e.g. 403 + reason). */
    public static ProcessingResponse block(int httpStatus, String reason) {
        ImmediateResponse immediate = ImmediateResponse.newBuilder()
                .setStatus(HttpStatus.newBuilder().setCode(StatusCode.forNumber(httpStatus)))
                .setBody(ByteString.copyFrom(reason, StandardCharsets.UTF_8))
                .build();
        return ProcessingResponse.newBuilder().setImmediateResponse(immediate).build();
    }

    /**
     * Block the Egress with an immediate HTTP response carrying an explicit body and
     * {@code content-type} (Coach: a Provider-shaped, model-legible 403 body). The body is
     * content-free by construction — rendered from the block status and rule-class names
     * only  — so nothing inspected reaches the wire here.
     */
    public static ProcessingResponse block(int httpStatus, byte[] body, String contentType) {
        HeaderValueOption ct = HeaderValueOption.newBuilder()
                .setHeader(HeaderValue.newBuilder()
                        .setKey("content-type")
                        .setRawValue(ByteString.copyFromUtf8(contentType)))
                .setAppendAction(HeaderValueOption.HeaderAppendAction.OVERWRITE_IF_EXISTS_OR_ADD)
                .build();
        ImmediateResponse immediate = ImmediateResponse.newBuilder()
                .setStatus(HttpStatus.newBuilder().setCode(StatusCode.forNumber(httpStatus)))
                .setHeaders(HeaderMutation.newBuilder().addSetHeaders(ct))
                .setBody(ByteString.copyFrom(body))
                .build();
        return ProcessingResponse.newBuilder().setImmediateResponse(immediate).build();
    }
}
