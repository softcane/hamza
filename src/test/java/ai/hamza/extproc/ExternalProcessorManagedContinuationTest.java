package ai.hamza.extproc;

import ai.hamza.adapter.OpenAiResponsesAdapter;
import ai.hamza.adapter.AnthropicMessagesAdapter;
import ai.hamza.adapter.ProviderAdapter;
import ai.hamza.config.HamzaProperties;
import ai.hamza.continuation.ByteCount;
import ai.hamza.continuation.ManagedMetadataSignature;
import ai.hamza.continuation.ManagedMetadataVerifier;
import ai.hamza.continuation.QuarantineBudget;
import ai.hamza.continuation.WorkflowProfile;
import ai.hamza.continuation.WorkflowShape;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.edm.Fingerprinter;
import ai.hamza.edm.RegistryRecipe;
import ai.hamza.edm.ReplacementKind;
import ai.hamza.edm.TypedRegistry;
import ai.hamza.metrics.HamzaMetrics;
import ai.hamza.masking.MaskContinuationService;
import ai.hamza.masking.MaskDetectionService;
import ai.hamza.masking.MaskPlanner;
import ai.hamza.masking.MaskScopeStore;
import ai.hamza.persistence.TurnRepository;
import ai.hamza.persistence.TurnAppendReceipt;
import ai.hamza.persistence.TurnRecord;
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

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Through-transport proof of the one managed behavior: every enforcing Finding —
 * secret, EDM, and (in the Presidio gate) approved PII — masks to a stable
 * Placeholder and the Agent continues; everything unprovable fails closed.
 */
class ExternalProcessorManagedContinuationTest {

    private static final String PROTECTED = "priya.fixture@example-corp.test";
    private static final String PROTECTED_SECOND = "marcus.fixture@example-corp.test";
    private static final byte[] SALT = "01234567890123456789012345678901"
            .getBytes(StandardCharsets.UTF_8);
    private static final byte[] METADATA_KEY = "managed-metadata-key-32-bytes!!"
            .getBytes(StandardCharsets.UTF_8);
    private static final Instant NOW = Instant.parse("2026-07-11T10:00:00Z");
    private static final String RECIPE_ID = "synthetic-email";
    private static final int RECIPE_VERSION = 1;
    private static final WorkflowProfile PROFILE = new WorkflowProfile(
            "repo-safe-edit", 1, "codex", "openai", "gpt-5-codex", "codex-0.144",
            RECIPE_ID, RECIPE_VERSION, WorkflowShape.ONE_WAY);
    private static final WorkflowProfile CLAUDE_PROFILE = new WorkflowProfile(
            "repo-safe-claude", 1, "claude-code", "anthropic",
            "claude-haiku-4-5-20251001", "claude-code-2.1.206",
            RECIPE_ID, RECIPE_VERSION, WorkflowShape.ONE_WAY);

    @Test
    void registryHitUnderBlockActionMasksAndContinuesWithLinkedRecords(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("managed.db"), 8 * 1024 * 1024)) {
            String body = body("Review café for " + PROTECTED + " twice " + PROTECTED);
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(body.getBytes(StandardCharsets.UTF_8).length,
                            true, false, "scope-0000000001"),
                    body(body, true), responseHeaders(), responseBody()));

            assertThat(responses).hasSize(4);
            ProcessingResponse headerResponse = responses.getFirst();
            assertThat(headerResponse.getModeOverride().getRequestBodyMode())
                    .isEqualTo(ProcessingMode.BodySendMode.BUFFERED);
            assertThat(headerResponse.getRequestHeaders().getResponse()
                    .getHeaderMutation().getRemoveHeadersList())
                    .containsExactlyInAnyOrderElementsOf(ManagedMetadataVerifier.internalHeaderNames())
                    .doesNotContain("authorization");

            ProcessingResponse bodyResponse = responses.get(1);
            assertThat(bodyResponse.getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
            byte[] derived = bodyResponse.getRequestBody().getResponse()
                    .getBodyMutation().getBody().toByteArray();
            String derivedText = new String(derived, StandardCharsets.UTF_8);
            assertThat(derivedText).doesNotContain(PROTECTED)
                    .containsPattern("<EMAIL_[0-9]+>");
            var placeholders = Pattern.compile("<EMAIL_[0-9]+>").matcher(derivedText)
                    .results().map(java.util.regex.MatchResult::group).distinct().toList();
            assertThat(placeholders).hasSize(1);
            assertThat(bodyResponse.getRequestBody().getResponse().getHeaderMutation()
                    .getRemoveHeadersList()).contains("transfer-encoding", "content-encoding");

            assertThat(harness.jdbc.sql("SELECT COUNT(*) FROM turns")
                    .query(Integer.class).single()).isEqualTo(2);
            assertThat(harness.jdbc.sql("""
                    SELECT record_role || ':' || action || ':' || request_bytes_egressed
                    FROM turns ORDER BY seq
                    """).query(String.class).list())
                    .containsExactly("SOURCE:MASK:0", "DERIVED:FLAG:" + derived.length);
            assertThat(harness.jdbc.sql("""
                    SELECT COUNT(*) FROM turns source JOIN turns derived
                      ON derived.parent_turn_id = source.turn_id
                     AND derived.recovery_id = source.recovery_id
                    WHERE source.record_role = 'SOURCE' AND derived.record_role = 'DERIVED'
                    """).query(Integer.class).single()).isEqualTo(1);
            assertThat(harness.jdbc.sql("SELECT COUNT(*) FROM turns WHERE hash_version = 'hamza-record/v5'")
                    .query(Integer.class).single()).isEqualTo(2);
            assertThat(harness.jdbc.sql("""
                    SELECT DISTINCT turns.record_role || ':' || detector_runs.detector || ':'
                           || detector_runs.status
                    FROM turns JOIN detector_runs ON detector_runs.turn_id = turns.turn_id
                    ORDER BY 1
                    """).query(String.class).list()).containsExactly(
                            "DERIVED:edm:COMPLETE", "DERIVED:secret:COMPLETE",
                            "SOURCE:edm:COMPLETE", "SOURCE:secret:COMPLETE");
            assertThat(harness.jdbc.sql(
                    "SELECT masked_value_count FROM turns WHERE record_role = 'SOURCE'")
                    .query(Integer.class).single()).isEqualTo(2);
        }
    }

    @Test
    void chunkedTransferThresholdIsFullyBufferedWithZeroSourceEgress(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("managed-chunked.db"), 8 * 1024 * 1024)) {
            String source = body("Review " + PROTECTED);
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(null, true, true, "scope-chunked-0001"),
                    body(source, true),
                    responseHeaders(), responseBody()));

            assertThat(responses).hasSize(4);
            assertThat(responses.getFirst().getModeOverride().getRequestBodyMode())
                    .isEqualTo(ProcessingMode.BodySendMode.BUFFERED);
            ProcessingResponse derivedResponse = responses.get(1);
            assertThat(derivedResponse.getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
            String derived = derivedResponse.getRequestBody().getResponse()
                    .getBodyMutation().getBody().toStringUtf8();
            assertThat(derived).doesNotContain(PROTECTED)
                    .containsPattern("<EMAIL_[0-9]+>");
            assertThat(harness.jdbc.sql("""
                    SELECT record_role || ':' || action || ':' || request_bytes_egressed
                    FROM turns ORDER BY seq
                    """).query(String.class).list())
                    .containsExactly("SOURCE:MASK:0",
                            "DERIVED:FLAG:" + derived.getBytes(StandardCharsets.UTF_8).length);
            assertThat(harness.jdbc.sql("""
                    SELECT COUNT(*) FROM findings WHERE rule = 'partial-egress'
                    """).query(Integer.class).single()).isZero();
        }
    }

    @Test
    void postResponseStreamErrorDoesNotEraseCompletedMaskScope(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("completed-teardown.db"), 8 * 1024 * 1024)) {
            String first = body("first " + PROTECTED);
            List<ProcessingResponse> firstResponses = directExchangeWithTeardownError(
                    harness.service, List.of(
                            headers(first.length(), true, false, "scope-completed-0001"),
                            body(first, true), responseHeaders(), responseBody()));
            String firstPlaceholder = placeholderFor(derivedBody(firstResponses.get(1)),
                    PROTECTED);

            // The same value masks after the teardown error. A surviving scope reuses
            // its Placeholder; an erased scope would re-seed and render a new one.
            String later = body("later " + PROTECTED);
            List<ProcessingResponse> laterResponses = exchange(harness.channel, List.of(
                    headers(later.length(), true, false, "scope-completed-0001"),
                    body(later, true), responseHeaders(), responseBody()));

            String derived = derivedBody(laterResponses.get(1));
            assertThat(placeholderFor(derived, PROTECTED)).isEqualTo(firstPlaceholder);
        }
    }

    @Test
    void managedCompletionBeforeBodyRecordsSourceDetectorGaps(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("missing-body.db"), 8 * 1024 * 1024)) {
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(null, true, true, "scope-missing-body-01")));

            assertThat(responses).singleElement().satisfies(response ->
                    assertThat(response.getModeOverride().getRequestBodyMode())
                            .isEqualTo(ProcessingMode.BodySendMode.BUFFERED));
            assertThat(harness.jdbc.sql("SELECT record_role || ':' || action FROM turns")
                    .query(String.class).single()).isEqualTo("SOURCE:BLOCK");
            assertThat(harness.jdbc.sql("""
                    SELECT detector || ':' || status || ':' || reason
                    FROM detector_runs ORDER BY detector
                    """).query(String.class).list()).containsExactly(
                            "edm:SKIPPED:UPSTREAM_BLOCK",
                            "secret:SKIPPED:UPSTREAM_BLOCK");
        }
    }

    @Test
    void fullyScannedFindingFreeManagedTurnPassesThrough(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("clean-managed.db"), 8 * 1024 * 1024)) {
            String source = body("Ask to read the local fixture first.");
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(source.length(), true, false, "scope-clean-first-0001"),
                    body(source, true), responseHeaders(), responseBody()));

            assertThat(responses.get(1).getRequestBody().getResponse().hasBodyMutation()).isFalse();
            assertThat(harness.jdbc.sql("""
                    select record_role || ':' || action || ':' || request_bytes_egressed
                    from turns order by seq
                    """).query(String.class).list())
                    .containsExactly("STANDARD:FLAG:" + source.length());
            assertThat(harness.jdbc.sql("select count(*) from findings")
                    .query(Integer.class).single()).isZero();

            // A clean Turn is not consumed: the identical resend still passes.
            List<ProcessingResponse> resend = exchange(harness.channel, List.of(
                    headers(source.length(), true, false, "scope-clean-first-0001"),
                    body(source, true), responseHeaders(), responseBody()));
            assertThat(resend.get(1).getRequestBody().getResponse().hasBodyMutation()).isFalse();
        }
    }

    @Test
    void signedZeroBodyManagedRequestCompletesAtHeadersAndRecordsProviderEgress(
            @TempDir Path temp) throws Exception {
        try (Harness harness = start(temp.resolve("zero-body-managed.db"), 8 * 1024 * 1024)) {
            ProcessingRequest base = headers(0, true, false, "scope-zero-body-0001");
            ProcessingRequest zeroBody = base.toBuilder()
                    .setRequestHeaders(base.getRequestHeaders().toBuilder().setEndOfStream(true))
                    .build();

            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    zeroBody, responseHeaders(), responseBody()));

            assertThat(responses.getFirst().getModeOverride().getRequestBodyMode())
                    .isEqualTo(ProcessingMode.BodySendMode.NONE);
            assertThat(responses.getFirst().getRequestHeaders().getResponse()
                    .getHeaderMutation().getRemoveHeadersList())
                    .containsExactlyInAnyOrderElementsOf(
                            ManagedMetadataVerifier.internalHeaderNames());
            assertThat(harness.jdbc.sql("""
                    select record_role || ':' || action || ':' || request_bytes_egressed
                    from turns
                    """).query(String.class).single()).isEqualTo("STANDARD:FLAG:0");
            assertThat(harness.jdbc.sql("select count(*) from findings")
                    .query(Integer.class).single()).isZero();
        }
    }

    @Test
    void certifiedClaudeCodeTupleUsesTheAnthropicManagedPath(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("claude-managed.db"), 8 * 1024 * 1024,
                false, CLAUDE_PROFILE, new AnthropicMessagesAdapter())) {
            String source = anthropicBody(PROTECTED + " twice " + PROTECTED);
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(source.getBytes(StandardCharsets.UTF_8).length, true, false,
                            "scope-claude-0000001", null, "/v1/messages", CLAUDE_PROFILE,
                            "claude-code/2.1.206"),
                    body(source, true)));

            assertThat(responses).hasSize(2);
            assertThat(responses.getFirst().getModeOverride().getRequestBodyMode())
                    .isEqualTo(ProcessingMode.BodySendMode.BUFFERED);
            String derived = responses.get(1).getRequestBody().getResponse()
                    .getBodyMutation().getBody().toStringUtf8();
            assertThat(derived).doesNotContain(PROTECTED)
                    .containsPattern("<EMAIL_[0-9]+>");
            assertThat(harness.jdbc.sql("""
                    SELECT record_role || ':' || action || ':' || request_bytes_egressed
                    FROM turns ORDER BY seq
                    """).query(String.class).list())
                    .containsExactly("SOURCE:MASK:0", "DERIVED:FLAG:"
                            + derived.getBytes(StandardCharsets.UTF_8).length);
        }
    }

    @Test
    void maskContinuationE2ECapturesOnlyStablePlaceholdersForBothProviders(@TempDir Path temp)
            throws Exception {
        String fakeSecret = "AKIAABCDEFGHIJKLMNOP";
        try (Harness harness = startMask(temp.resolve("mask-openai.db"), PROFILE,
                new OpenAiResponsesAdapter())) {
            String firstSource = body(PROTECTED + " twice " + PROTECTED + " secret " + fakeSecret);
            String firstCapture = capturedRequestBody(exchange(harness.channel, List.of(
                    headers(firstSource.getBytes(StandardCharsets.UTF_8).length, true, false,
                            "scope-mask-openai-01"), body(firstSource, true))));
            String laterSource = body("later " + PROTECTED + " secret " + fakeSecret);
            String laterCapture = capturedRequestBody(exchange(harness.channel, List.of(
                    headers(laterSource.getBytes(StandardCharsets.UTF_8).length, true, false,
                            "scope-mask-openai-01"), body(laterSource, true))));

            assertCapturedMask(firstCapture, laterCapture, fakeSecret);
            assertThat(harness.jdbc.sql("""
                    SELECT record_role || ':' || action || ':' || request_bytes_egressed
                    FROM turns ORDER BY seq
                    """).query(String.class).list()).containsExactly(
                            "SOURCE:MASK:0", "DERIVED:FLAG:" + firstCapture.length(),
                            "SOURCE:MASK:0", "DERIVED:FLAG:" + laterCapture.length());
            assertThat(harness.jdbc.sql("""
                    SELECT masked_value_count FROM turns
                    WHERE record_role = 'SOURCE' ORDER BY seq
                    """)
                    .query(Integer.class).list()).allMatch(count -> count > 0);
        }

        try (Harness harness = startMask(temp.resolve("mask-anthropic.db"), CLAUDE_PROFILE,
                new AnthropicMessagesAdapter())) {
            String firstSource = anthropicBody(PROTECTED + " twice " + PROTECTED
                    + " secret " + fakeSecret);
            String firstCapture = capturedRequestBody(exchange(harness.channel, List.of(
                    headers(firstSource.getBytes(StandardCharsets.UTF_8).length, true, false,
                            "scope-mask-anthropic-01", null, "/v1/messages", CLAUDE_PROFILE,
                            "claude-code/2.1.206"), body(firstSource, true))));
            String laterSource = anthropicBody("later " + PROTECTED + " secret " + fakeSecret);
            String laterCapture = capturedRequestBody(exchange(harness.channel, List.of(
                    headers(laterSource.getBytes(StandardCharsets.UTF_8).length, true, false,
                            "scope-mask-anthropic-01", null, "/v1/messages", CLAUDE_PROFILE,
                            "claude-code/2.1.206"), body(laterSource, true))));

            assertCapturedMask(firstCapture, laterCapture, fakeSecret);
        }
    }

    @Test
    void unknownLengthStillBuffersAndKnownOrObservedOverboundBodiesBlock(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("bounds.db"), 1024)) {
            String safeSize = body(PROTECTED);
            List<ProcessingResponse> unknown = exchange(harness.channel, List.of(
                    headers(null, true, true, "scope-0000000001"), body(safeSize, true)));
            assertThat(unknown.getFirst().getModeOverride().getRequestBodyMode())
                    .isEqualTo(ProcessingMode.BodySendMode.BUFFERED);
            assertThat(unknown.get(1).getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);

            List<ProcessingResponse> known = exchange(harness.channel, List.of(
                    headers(2048, true, false, "scope-0000000002")));
            assertThat(known).singleElement().satisfies(response ->
                    assertThat(response.getResponseCase())
                            .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE));

            String overbound = "x".repeat(1100);
            List<ProcessingResponse> observed = exchange(harness.channel, List.of(
                    headers(null, true, true, "scope-0000000003"), body(overbound, true)));
            assertThat(observed.get(1).getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(observed.get(1).getImmediateResponse().getBody().toStringUtf8())
                    .doesNotContain(overbound);
        }
    }

    @Test
    void partialCompressedForgedAndUnknownProviderManagedTurnsFailClosed(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("failures.db"), 8 * 1024 * 1024)) {
            String requestBody = body(PROTECTED);
            List<ProcessingResponse> partial = exchange(harness.channel, List.of(
                    headers(null, true, true, "scope-0000000001"), body(requestBody, false)));
            assertThat(partial.get(1).getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(harness.jdbc.sql("""
                    SELECT detector_runs.detector || ':' || detector_runs.status || ':'
                           || detector_runs.reason
                    FROM detector_runs JOIN turns ON turns.turn_id = detector_runs.turn_id
                    WHERE turns.record_role = 'SOURCE'
                    ORDER BY detector
                    """).query(String.class).list()).containsExactly(
                            "edm:SKIPPED:UPSTREAM_BLOCK",
                            "secret:SKIPPED:UPSTREAM_BLOCK");

            List<ProcessingResponse> compressed = exchange(harness.channel, List.of(
                    headers(requestBody.length(), true, false, "scope-0000000002", "gzip",
                            "/v1/responses")));
            assertThat(compressed.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);

            List<ProcessingResponse> forged = exchange(harness.channel, List.of(
                    headers(requestBody.length(), false, false, "scope-0000000003")));
            assertThat(forged.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);

            List<ProcessingResponse> unknownProvider = exchange(harness.channel, List.of(
                    headers(requestBody.length(), true, false, "scope-0000000004", null,
                            "/v1/unknown")));
            assertThat(unknownProvider.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(harness.jdbc.sql("""
                    SELECT COUNT(*) FROM turns
                    WHERE record_role = 'STANDARD'
                      AND 2 = (SELECT COUNT(*) FROM detector_runs
                               WHERE detector_runs.turn_id = turns.turn_id)
                    """).query(Integer.class).single()).isEqualTo(3);
        }
    }

    @Test
    void identicalRetryMasksAgainToTheByteIdenticalDerivedBody(@TempDir Path temp)
            throws Exception {
        // A real CLI Agent fires identical bodies more than once by design (parallel
        // side calls, transport retries), so a repeat must continue — and because the
        // Mask Scope renders stable Placeholders, the repeat egress must be
        // byte-identical: the retry releases nothing the first Turn did not.
        try (Harness harness = start(temp.resolve("idempotent-retry.db"), 8 * 1024 * 1024)) {
            String requestBody = body(PROTECTED);
            List<ProcessingRequest> first = List.of(
                    headers(requestBody.length(), true, false, "scope-0000000001"),
                    body(requestBody, true), responseHeaders(), responseBody());
            String firstDerived = derivedBody(exchange(harness.channel, first).get(1));

            List<ProcessingResponse> retry = exchange(harness.channel, List.of(
                    headers(requestBody.length(), true, false, "scope-0000000001"),
                    body(requestBody, true), responseHeaders(), responseBody()));
            assertThat(derivedBody(retry.get(1))).isEqualTo(firstDerived);
            assertThat(harness.jdbc.sql("SELECT COUNT(*) FROM turns WHERE record_role = 'DERIVED'")
                    .query(Integer.class).single()).isEqualTo(2);
        }
    }

    @Test
    void protectedValueOutsideAdapterSegmentsFailsTheCompleteFinalScan(@TempDir Path temp)
            throws Exception {
        // The registered value hides in a tool description the Adapter does not
        // collect as a maskable segment, while the input occurrence masks cleanly.
        // Only the complete-DERIVED-body rescan can catch it, and it must fail closed.
        String dirty = body(PROTECTED).replace("safe fake tool", PROTECTED);
        try (Harness harness = start(temp.resolve("dirty.db"), 8 * 1024 * 1024)) {
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(dirty.length(), true, false, "scope-0000000001"),
                    body(dirty, true)));
            assertThat(responses.get(1).getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(harness.jdbc.sql("SELECT COUNT(*) FROM turns WHERE record_role = 'DERIVED'")
                    .query(Integer.class).single()).isZero();
            assertThat(harness.jdbc.sql("SELECT request_bytes_egressed FROM turns")
                    .query(Long.class).single()).isZero();
            assertThat(harness.jdbc.sql(
                    "SELECT COUNT(*) FROM findings WHERE rule = 'continuation-failed'")
                    .query(Integer.class).single()).isEqualTo(1);
        }

        try (Harness harness = start(temp.resolve("commit-fail.db"), 8 * 1024 * 1024, true)) {
            String source = body(PROTECTED);
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(source.length(), true, false, "scope-0000000002"),
                    body(source, true)));
            assertThat(responses.get(1).getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(harness.jdbc.sql("SELECT COUNT(*) FROM turns")
                    .query(Integer.class).single()).isZero();
        }
    }

    @Test
    void flagOnlyFindingOutsideAdapterSegmentsDoesNotDirtyFinalScan(@TempDir Path temp)
            throws Exception {
        String flagOnly = body(PROTECTED).replace("safe fake tool",
                "safe fake tool AKIAABCDEFGHIJKLMNOP");
        try (Harness harness = start(temp.resolve("flag-final-scan.db"), 8 * 1024 * 1024)) {
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(flagOnly.length(), true, false, "scope-flag-final-0001"),
                    body(flagOnly, true), responseHeaders(), responseBody()));

            String derived = derivedBody(responses.get(1));
            assertThat(derived).doesNotContain(PROTECTED)
                    .containsPattern("<EMAIL_[0-9]+>");
            assertThat(harness.jdbc.sql("""
                    SELECT record_role || ':' || action || ':' || request_bytes_egressed
                    FROM turns ORDER BY seq
                    """).query(String.class).list())
                    .containsExactly("SOURCE:MASK:0",
                            "DERIVED:FLAG:" + derived.getBytes(StandardCharsets.UTF_8).length);
        }
    }

    @Test
    void findingWithoutAMaskableSpanFailsClosed(@TempDir Path temp) throws Exception {
        try (Harness harness = start(temp.resolve("unmaskable.db"), 8 * 1024 * 1024)) {
            // The fake AWS key's rule keeps the default FLAG action in this harness:
            // a Finding without a Mask candidate. The managed route never forwards a
            // found raw value, so the Turn fails closed instead of passing flagged.
            String source = body("key AKIAABCDEFGHIJKLMNOP");
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(source.length(), true, false, "scope-unmaskable-0001"),
                    body(source, true)));
            assertThat(responses.get(1).getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(harness.jdbc.sql("SELECT record_role || ':' || action FROM turns")
                    .query(String.class).single()).isEqualTo("SOURCE:BLOCK");
            assertThat(harness.jdbc.sql(
                    "SELECT COUNT(*) FROM findings WHERE rule = 'continuation-ineligible'")
                    .query(Integer.class).single()).isEqualTo(1);
        }
    }

    // ---- R1 characterization: managed header-admission rejections (seam group 1) ----

    @Test
    void disabledManagedRuntimeRejectsManagedHeaders(@TempDir Path temp) throws Exception {
        // managedRuntime.enabled() == false, but the client still sends signed managed
        // metadata headers: the Gate must fail closed with the ineligibility rule rather
        // than silently falling back to the standard route.
        try (Harness harness = startDisabledManagedRuntime(temp.resolve("runtime-disabled.db"))) {
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(0, true, false, "scope-runtime-disabled-01")));
            assertThat(responses.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(responses.getFirst().getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.CONTINUATION_INELIGIBLE_RULE);
        }
    }

    @Test
    void profileAgentMismatchAgainstTheInferredUserAgentRejectsManagedHeaders(@TempDir Path temp)
            throws Exception {
        // The signed profile is internally consistent (codex/openai/gpt-5-codex) and its
        // signature verifies, but the User-Agent on THIS request identifies a different
        // Agent: the certified tuple no longer matches what is actually calling.
        try (Harness harness = start(temp.resolve("agent-mismatch.db"), 8 * 1024 * 1024)) {
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(0, true, false, "scope-agent-mismatch-01", null, "/v1/responses",
                            PROFILE, "claude-code/2.1.206")));
            assertThat(responses.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(responses.getFirst().getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.MANAGED_METADATA_RULE);
        }
    }

    @Test
    void nonIdentityContentEncodingRejectsManagedHeadersAsOpaqueContent(@TempDir Path temp)
            throws Exception {
        // Contract example: a managed request carrying content-encoding: gzip cannot be
        // quarantined byte-for-byte (the wire bytes are not the content), so it Blocks
        // opaque-content at the header stage rather than buffering an unreadable body.
        try (Harness harness = start(temp.resolve("gzip-header.db"), 8 * 1024 * 1024)) {
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(64, true, false, "scope-gzip-header-01", "gzip", "/v1/responses")));
            assertThat(responses.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(responses.getFirst().getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.OPAQUE_CONTENT_RULE);
        }
    }

    @Test
    void duplicatedContentLengthOrTransferEncodingRejectsManagedHeaders(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("duplicated-header.db"), 8 * 1024 * 1024)) {
            List<ProcessingResponse> duplicateContentLength = exchange(harness.channel, List.of(
                    customHeaders("scope-dup-cl-0001", PROFILE, List.of(
                            Map.entry("content-length", "10"), Map.entry("content-length", "20")))));
            assertThat(duplicateContentLength.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(duplicateContentLength.getFirst().getImmediateResponse().getBody()
                    .toStringUtf8()).contains(TurnState.MANAGED_QUARANTINE_RULE);

            List<ProcessingResponse> duplicateTransferEncoding = exchange(harness.channel, List.of(
                    customHeaders("scope-dup-te-0001", PROFILE, List.of(
                            Map.entry("transfer-encoding", "chunked"),
                            Map.entry("transfer-encoding", "chunked")))));
            assertThat(duplicateTransferEncoding.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(duplicateTransferEncoding.getFirst().getImmediateResponse().getBody()
                    .toStringUtf8()).contains(TurnState.MANAGED_QUARANTINE_RULE);
        }
    }

    @Test
    void nonChunkedTransferEncodingRejectsManagedHeaders(@TempDir Path temp) throws Exception {
        try (Harness harness = start(temp.resolve("bad-transfer-encoding.db"), 8 * 1024 * 1024)) {
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    customHeaders("scope-bad-te-0001", PROFILE, List.of(
                            Map.entry("transfer-encoding", "gzip")))));
            assertThat(responses.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(responses.getFirst().getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.MANAGED_QUARANTINE_RULE);
        }
    }

    @Test
    void transferEncodingAlongsideContentLengthRejectsManagedHeaders(@TempDir Path temp)
            throws Exception {
        try (Harness harness = start(temp.resolve("te-plus-cl.db"), 8 * 1024 * 1024)) {
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    customHeaders("scope-te-plus-cl-01", PROFILE, List.of(
                            Map.entry("transfer-encoding", "chunked"),
                            Map.entry("content-length", "10")))));
            assertThat(responses.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(responses.getFirst().getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.MANAGED_QUARANTINE_RULE);
        }
    }

    @Test
    void nonNumericContentLengthRejectsManagedHeaders(@TempDir Path temp) throws Exception {
        try (Harness harness = start(temp.resolve("non-numeric-cl.db"), 8 * 1024 * 1024)) {
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    customHeaders("scope-non-numeric-cl-01", PROFILE, List.of(
                            Map.entry("content-length", "not-a-number")))));
            assertThat(responses.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(responses.getFirst().getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.MANAGED_QUARANTINE_RULE);
        }
    }

    @Test
    void quarantineReservationDenialRejectsManagedHeadersOnceConcurrencyIsExhausted(
            @TempDir Path temp) throws Exception {
        // maxConcurrent=1: the first managed Turn holds its reservation open (its stream
        // never completes), so a second concurrent managed Turn's reservation attempt is
        // denied outright rather than silently queued or admitted over budget.
        try (Harness harness = startWithSingleConcurrentQuarantineSlot(
                temp.resolve("quarantine-denied.db"))) {
            List<ProcessingResponse> firstResponses = new ArrayList<>();
            StreamObserver<ProcessingRequest> firstRequests = harness.service.process(
                    new StreamObserver<>() {
                        @Override public void onNext(ProcessingResponse value) {
                            firstResponses.add(value);
                        }
                        @Override public void onError(Throwable error) { }
                        @Override public void onCompleted() { }
                    });
            firstRequests.onNext(headers(null, true, true, "scope-quarantine-holder-01"));
            assertThat(firstResponses.getFirst().getModeOverride().getRequestBodyMode())
                    .isEqualTo(ProcessingMode.BodySendMode.BUFFERED);

            List<ProcessingResponse> secondResponses = exchange(harness.channel, List.of(
                    headers(null, true, true, "scope-quarantine-denied-01")));
            assertThat(secondResponses.getFirst().getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(secondResponses.getFirst().getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.MANAGED_QUARANTINE_RULE);
        }
    }

    // ---- R1 characterization: managed body rejections (seam group 2) ----

    @Test
    void declaredContentLengthNotMatchingObservedBytesRejectsManagedBody(@TempDir Path temp)
            throws Exception {
        // The declared content-length (50) fits comfortably inside the quarantine
        // reservation, but only 40 bytes actually arrive: a wire-level mismatch the
        // managed route must not silently accept as "close enough".
        try (Harness harness = start(temp.resolve("declared-length-mismatch.db"), 8 * 1024 * 1024)) {
            String source = "x".repeat(40);
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(50, true, false, "scope-declared-mismatch-01"), body(source, true)));
            assertThat(responses.get(1).getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(responses.get(1).getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.MANAGED_QUARANTINE_RULE);
        }
    }

    @Test
    void requestedModelDivergingFromTheCertifiedProfileRejectsManagedBodyAsWireDrift(
            @TempDir Path temp) throws Exception {
        // The certified WorkflowProfile names gpt-5-codex; a body that requests a
        // different model mid-stream is the Adapter/Provider silently drifting off the
        // approved tuple, not a Finding the standard scan would ever produce.
        try (Harness harness = start(temp.resolve("model-wire-drift.db"), 8 * 1024 * 1024)) {
            String driftedBody = """
                    {"model":"gpt-4o-not-certified","instructions":"Use the fake fixture.",\
                    "input":"Ask to read the local fixture first.","tools":[{"type":"function",\
                    "name":"check_fixture","description":"safe fake tool",\
                    "parameters":{"type":"object"}}]}
                    """.strip();
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(driftedBody.length(), true, false, "scope-model-drift-01"),
                    body(driftedBody, true)));
            assertThat(responses.get(1).getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(responses.get(1).getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.WIRE_DRIFT_RULE);
        }
    }

    // ---- R1 characterization: record-commit failure inside the session (seam group 3) ----

    @Test
    void recordCommitFailureDuringMaskedSourceAppendEmitsRecordCommitFailedBlock(
            @TempDir Path temp) throws Exception {
        // appendManagedMaskSource's RuntimeException catch (DefaultTurnPipelineSession
        // 452-464): the repository throws while committing the masked SOURCE row, so the
        // Turn must Block with record-commit-failed and leave nothing durable behind
        // rather than half-commit or silently continue past an unrecorded Mask Scope.
        try (Harness harness = start(temp.resolve("record-commit-failure.db"),
                8 * 1024 * 1024, true)) {
            String source = body(PROTECTED);
            List<ProcessingResponse> responses = exchange(harness.channel, List.of(
                    headers(source.length(), true, false, "scope-record-commit-fail-01"),
                    body(source, true)));
            assertThat(responses.get(1).getResponseCase())
                    .isEqualTo(ProcessingResponse.ResponseCase.IMMEDIATE_RESPONSE);
            assertThat(responses.get(1).getImmediateResponse().getBody().toStringUtf8())
                    .contains(TurnState.RECORD_COMMIT_RULE);
            assertThat(harness.jdbc.sql("SELECT COUNT(*) FROM turns")
                    .query(Integer.class).single()).isZero();
        }
    }

    private static Harness startDisabledManagedRuntime(Path db) throws Exception {
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository repository = new TurnRepository(jdbc);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        HamzaProperties properties = new HamzaProperties(
                new HamzaProperties.Metrics(Map.of()),
                new HamzaProperties.Policy(Action.FLAG, Map.of("edm-customers", Action.BLOCK),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true));
        HamzaMetrics metrics = new HamzaMetrics(meterRegistry, properties);
        PolicyEngine policy = new PolicyEngine(new SecretDetector(), new Masker(), Action.FLAG,
                Map.of("edm-customers", Action.BLOCK));
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        ExternalProcessorService service = new ExternalProcessorService(
                new DefaultTurnPipeline(List.of(new OpenAiResponsesAdapter()), policy, repository,
                        metrics, new CoachSessionTracker(), new ReEncodedContentDetector(),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true,
                        ManagedContinuationRuntime.disabled()), coach);
        String name = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(name).directExecutor()
                .addService(service).build().start();
        ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        return new Harness(server, channel, jdbc, service);
    }

    private static Harness startWithSingleConcurrentQuarantineSlot(Path db) throws Exception {
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository repository = new TurnRepository(jdbc);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        Map<String, Action> ruleActions = Map.of("edm-customers", Action.BLOCK);
        HamzaProperties properties = new HamzaProperties(
                new HamzaProperties.Metrics(Map.of()),
                new HamzaProperties.Policy(Action.FLAG, ruleActions,
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true));
        HamzaMetrics metrics = new HamzaMetrics(meterRegistry, properties);
        SecretDetector detector = new SecretDetector();
        PolicyEngine policy = new PolicyEngine(detector, new Masker(), Action.FLAG, ruleActions);
        ManagedMetadataVerifier verifier = new ManagedMetadataVerifier(
                Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(5), Duration.ofSeconds(30),
                METADATA_KEY, List.of(PROFILE));
        int cap = 8 * 1024 * 1024;
        ManagedContinuationRuntime runtime = new ManagedContinuationRuntime(
                new ByteCount(cap), verifier,
                new QuarantineBudget(new ByteCount(cap), new ByteCount(cap * 4L), 1),
                new MaskContinuationService(
                        new MaskDetectionService(detector, new EdmMatcher(List.of(), List.of(), 50_000), policy),
                        new MaskPlanner(new MaskScopeStore()), new MaskScopeStore()));
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        ExternalProcessorService service = new ExternalProcessorService(
                new DefaultTurnPipeline(List.of(new OpenAiResponsesAdapter()), policy, repository,
                        metrics, new CoachSessionTracker(), new ReEncodedContentDetector(),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true, runtime), coach);
        String name = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(name).directExecutor()
                .addService(service).build().start();
        ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        return new Harness(server, channel, jdbc, service);
    }

    private static ProcessingRequest customHeaders(String recoveryId, WorkflowProfile profile,
                                                   List<Map.Entry<String, String>> extraHeaders) {
        Map<String, String> metadata = managedMetadata(recoveryId, profile);
        HeaderMap.Builder headers = HeaderMap.newBuilder()
                .addHeaders(header(":path", "/v1/responses"))
                .addHeaders(header("user-agent", "codex_cli_rs/0.144.0"))
                .addHeaders(header("authorization", "Bearer AKIAABCDEFGHIJKLMNOP"));
        extraHeaders.forEach(e -> headers.addHeaders(header(e.getKey(), e.getValue())));
        metadata.forEach((name, value) -> headers.addHeaders(header(name, value)));
        return ProcessingRequest.newBuilder()
                .setRequestHeaders(HttpHeaders.newBuilder().setHeaders(headers)).build();
    }

    private static Harness start(Path db, int managedMaxBytes) throws Exception {
        return start(db, managedMaxBytes, false);
    }

    private static Harness start(Path db, int managedMaxBytes, boolean failSourceCommit)
            throws Exception {
        return start(db, managedMaxBytes, failSourceCommit, PROFILE,
                new OpenAiResponsesAdapter());
    }

    private static Harness startMask(Path db, WorkflowProfile profile,
                                     ProviderAdapter adapter) throws Exception {
        return start(db, 65_536, false, profile, adapter, true);
    }

    private static Harness start(Path db, int managedMaxBytes, boolean failSourceCommit,
                                 WorkflowProfile profile, ProviderAdapter adapter)
            throws Exception {
        return start(db, managedMaxBytes, failSourceCommit, profile, adapter, false);
    }

    private static Harness start(Path db, int managedMaxBytes, boolean failSourceCommit,
                                 WorkflowProfile profile, ProviderAdapter adapter,
                                 boolean maskActions) throws Exception {
        JdbcClient jdbc = jdbcOn(db);
        TurnRepository repository = failSourceCommit ? new TurnRepository(jdbc) {
            @Override
            public synchronized TurnAppendReceipt append(TurnRecord record) {
                if (record.continuation().role()
                        == ai.hamza.persistence.ContinuationEvidence.Role.SOURCE) {
                    throw new IllegalStateException("injected-source-commit-failure");
                }
                return super.append(record);
            }
        } : new TurnRepository(jdbc);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        // The default harness keeps the rule at BLOCK on purpose: the managed route
        // masks a Registry hit whatever the standard-route Action says.
        Map<String, Action> ruleActions = maskActions
                ? Map.of("edm-customers", Action.MASK, "aws-access-token", Action.MASK)
                : Map.of("edm-customers", Action.BLOCK);
        HamzaProperties properties = new HamzaProperties(
                new HamzaProperties.Metrics(Map.of()),
                new HamzaProperties.Policy(Action.FLAG, ruleActions,
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true));
        HamzaMetrics metrics = new HamzaMetrics(meterRegistry, properties);

        TypedRegistry typed = TypedRegistry.create("customers", SALT, 1,
                new RegistryRecipe(RECIPE_ID, RECIPE_VERSION),
                Map.of("email", new TypedRegistry.Field("email", ReplacementKind.EMAIL,
                        Set.of(Fingerprinter.fullFingerprint(SALT, PROTECTED),
                                Fingerprinter.fullFingerprint(SALT, PROTECTED_SECOND)))));
        EdmMatcher matcher = new EdmMatcher(List.of(), List.of(typed), 50_000);
        SecretDetector detector = new SecretDetector();
        PolicyEngine policy = new PolicyEngine(detector, new Masker(), Action.FLAG,
                ruleActions, matcher, 10);
        ManagedMetadataVerifier verifier = new ManagedMetadataVerifier(
                Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(5), Duration.ofSeconds(30),
                METADATA_KEY, List.of(profile));
        MaskScopeStore scopes = new MaskScopeStore();
        MaskContinuationService maskContinuation = new MaskContinuationService(
                new MaskDetectionService(detector, matcher, policy),
                new MaskPlanner(scopes), scopes);
        ManagedContinuationRuntime runtime = new ManagedContinuationRuntime(
                new ByteCount(managedMaxBytes), verifier,
                new QuarantineBudget(new ByteCount(managedMaxBytes),
                        new ByteCount(managedMaxBytes * 4L), 4), maskContinuation);
        CoachResponder coach = new CoachResponder(true, 403, Map.of());
        ExternalProcessorService service = new ExternalProcessorService(
                new DefaultTurnPipeline(List.of(adapter), policy, repository, metrics,
                        new CoachSessionTracker(), new ReEncodedContentDetector(),
                        HamzaProperties.DEFAULT_MAX_BODY_BYTES,
                        HamzaProperties.DEFAULT_CONTROL_PLANE_PATHS, true, runtime), coach);
        String name = InProcessServerBuilder.generateName();
        Server server = InProcessServerBuilder.forName(name).directExecutor()
                .addService(service).build().start();
        ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
        return new Harness(server, channel, jdbc, service);
    }

    private static JdbcClient jdbcOn(Path db) {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + db);
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            String schema = new String(ExternalProcessorManagedContinuationTest.class
                    .getResourceAsStream("/schema.sql").readAllBytes(), StandardCharsets.UTF_8);
            for (String sql : schema.split(";")) {
                if (!sql.isBlank()) {
                    statement.execute(sql);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return JdbcClient.create(dataSource);
    }

    private static List<ProcessingResponse> exchange(ManagedChannel channel,
                                                     List<ProcessingRequest> input)
            throws Exception {
        List<ProcessingResponse> output = new ArrayList<>();
        CountDownLatch completed = new CountDownLatch(1);
        StreamObserver<ProcessingRequest> requests = ExternalProcessorGrpc.newStub(channel)
                .process(new StreamObserver<>() {
                    @Override
                    public void onNext(ProcessingResponse value) {
                        output.add(value);
                    }

                    @Override
                    public void onError(Throwable error) {
                        completed.countDown();
                    }

                    @Override
                    public void onCompleted() {
                        completed.countDown();
                    }
                });
        input.forEach(requests::onNext);
        requests.onCompleted();
        assertThat(completed.await(5, TimeUnit.SECONDS)).isTrue();
        return output;
    }

    private static List<ProcessingResponse> directExchangeWithTeardownError(
            ExternalProcessorService service, List<ProcessingRequest> input) {
        List<ProcessingResponse> output = new ArrayList<>();
        StreamObserver<ProcessingRequest> requests = service.process(new StreamObserver<>() {
            @Override public void onNext(ProcessingResponse value) { output.add(value); }
            @Override public void onError(Throwable error) { }
            @Override public void onCompleted() { }
        });
        input.forEach(requests::onNext);
        requests.onError(new RuntimeException("post-response transport teardown"));
        return output;
    }

    private static String derivedBody(ProcessingResponse response) {
        assertThat(response.getResponseCase())
                .isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
        return response.getRequestBody().getResponse().getBodyMutation()
                .getBody().toStringUtf8();
    }

    private static String placeholderFor(String derived, String rawValue) {
        assertThat(derived).doesNotContain(rawValue);
        var matcher = Pattern.compile("<EMAIL_[0-9]+>").matcher(derived);
        assertThat(matcher.find()).isTrue();
        return matcher.group();
    }

    private static ProcessingRequest headers(Integer contentLength, boolean validSignature,
                                             boolean chunked, String recoveryId) {
        return headers(contentLength, validSignature, chunked, recoveryId, null,
                "/v1/responses");
    }

    private static ProcessingRequest headers(Integer contentLength, boolean validSignature,
                                             boolean chunked, String recoveryId,
                                             String contentEncoding, String path) {
        return headers(contentLength, validSignature, chunked, recoveryId, contentEncoding,
                path, PROFILE, "codex_cli_rs/0.144.0");
    }

    private static ProcessingRequest headers(Integer contentLength, boolean validSignature,
                                             boolean chunked, String recoveryId,
                                             String contentEncoding, String path,
                                             WorkflowProfile profile, String userAgent) {
        Map<String, String> metadata = managedMetadata(recoveryId, profile);
        if (!validSignature) {
            metadata.put(ManagedMetadataVerifier.SIGNATURE, "0".repeat(64));
        }
        HeaderMap.Builder headers = HeaderMap.newBuilder()
                .addHeaders(header(":path", path))
                .addHeaders(header("user-agent", userAgent))
                .addHeaders(header("authorization", "Bearer AKIAABCDEFGHIJKLMNOP"));
        if (contentLength != null) {
            headers.addHeaders(header("content-length", Integer.toString(contentLength)));
        }
        if (chunked) {
            headers.addHeaders(header("transfer-encoding", "chunked"));
        }
        if (contentEncoding != null) {
            headers.addHeaders(header("content-encoding", contentEncoding));
        }
        metadata.forEach((name, value) -> headers.addHeaders(header(name, value)));
        return ProcessingRequest.newBuilder()
                .setRequestHeaders(HttpHeaders.newBuilder().setHeaders(headers)).build();
    }

    private static Map<String, String> managedMetadata(String recoveryId,
                                                       WorkflowProfile profile) {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put(ManagedMetadataVerifier.RECOVERY_ID, recoveryId);
        fields.put(ManagedMetadataVerifier.PROFILE_ID, profile.id());
        fields.put(ManagedMetadataVerifier.PROFILE_VERSION, Integer.toString(profile.version()));
        fields.put(ManagedMetadataVerifier.AGENT, profile.agent());
        fields.put(ManagedMetadataVerifier.PROVIDER, profile.provider());
        fields.put(ManagedMetadataVerifier.MODEL, profile.model());
        fields.put(ManagedMetadataVerifier.ADAPTER_WIRE_VERSION, profile.adapterWireVersion());
        fields.put(ManagedMetadataVerifier.ISSUED_AT, Long.toString(NOW.getEpochSecond()));
        fields.put(ManagedMetadataVerifier.SIGNATURE,
                ManagedMetadataSignature.sign(fields, METADATA_KEY));
        return fields;
    }

    private static HeaderValue header(String name, String value) {
        return HeaderValue.newBuilder().setKey(name)
                .setRawValue(ByteString.copyFromUtf8(value)).build();
    }

    private static ProcessingRequest body(String value, boolean endOfStream) {
        return ProcessingRequest.newBuilder().setRequestBody(HttpBody.newBuilder()
                .setBody(ByteString.copyFromUtf8(value)).setEndOfStream(endOfStream)).build();
    }

    private static ProcessingRequest responseHeaders() {
        return ProcessingRequest.newBuilder().setResponseHeaders(HttpHeaders.newBuilder()
                .setHeaders(HeaderMap.newBuilder().addHeaders(header(":status", "200")))).build();
    }

    private static ProcessingRequest responseBody() {
        String response = """
                event: response.completed
                data: {"type":"response.completed","response":{"model":"gpt-5-codex",\
                "status":"completed","usage":{"input_tokens":2,"output_tokens":1,"total_tokens":3}}}

                data: [DONE]
                """;
        return ProcessingRequest.newBuilder().setResponseBody(HttpBody.newBuilder()
                .setBody(ByteString.copyFromUtf8(response)).setEndOfStream(true)).build();
    }

    private static String body(String input) {
        return """
                {"model":"gpt-5-codex","instructions":"Use the fake fixture.",\
                "input":"%s","tools":[{"type":"function","name":"check_fixture",\
                "description":"safe fake tool","parameters":{"type":"object"}}]}
                """.formatted(input).strip();
    }

    private static String anthropicBody(String input) {
        return """
                {"model":"claude-haiku-4-5-20251001","max_tokens":64,\
                "messages":[{"role":"user","content":"%s"}]}
                """.formatted(input).strip();
    }

    private static String capturedRequestBody(List<ProcessingResponse> responses) {
        assertThat(responses).hasSize(2);
        assertThat(responses.get(1).getResponseCase())
                .isEqualTo(ProcessingResponse.ResponseCase.REQUEST_BODY);
        return responses.get(1).getRequestBody().getResponse()
                .getBodyMutation().getBody().toStringUtf8();
    }

    private static void assertCapturedMask(String firstCapture, String laterCapture,
                                           String fakeSecret) {
        assertThat(firstCapture + laterCapture)
                .doesNotContain(PROTECTED, fakeSecret)
                .containsPattern("<EMAIL_[0-9]+>")
                .containsPattern("<SECRET_[0-9]+>");
        var firstEmail = Pattern.compile("<EMAIL_[0-9]+>").matcher(firstCapture);
        var laterEmail = Pattern.compile("<EMAIL_[0-9]+>").matcher(laterCapture);
        var firstSecret = Pattern.compile("<SECRET_[0-9]+>").matcher(firstCapture);
        var laterSecret = Pattern.compile("<SECRET_[0-9]+>").matcher(laterCapture);
        assertThat(firstEmail.find() && laterEmail.find()).isTrue();
        assertThat(firstSecret.find() && laterSecret.find()).isTrue();
        assertThat(laterEmail.group()).isEqualTo(firstEmail.group());
        assertThat(laterSecret.group()).isEqualTo(firstSecret.group());
    }

    private record Harness(Server server, ManagedChannel channel, JdbcClient jdbc,
                           ExternalProcessorService service)
            implements AutoCloseable {
        @Override
        public void close() {
            try {
                channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
                server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new AssertionError("interrupted while closing test harness", interrupted);
            }
        }
    }
}
