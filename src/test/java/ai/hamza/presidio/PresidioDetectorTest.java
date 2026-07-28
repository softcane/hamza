package ai.hamza.presidio;

import ai.hamza.adapter.ContentSegment;
import ai.hamza.policy.DetectionReason;
import ai.hamza.policy.DetectionStatus;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PresidioDetectorTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final PresidioProfile PROFILE =
            PresidioProfile.load(java.nio.file.Path.of("detector/presidio/approved-profile.json"));
    /** No committed profile carries an override; this one exists only to exercise M1. */
    private static final PresidioProfile PROFILE_WITH_OVERRIDE = new PresidioProfile(
            "broad-pii-en", 1, "en", 0.75, List.of("IP_ADDRESS", "EMAIL_ADDRESS"),
            Map.of("IP_ADDRESS", 0.6));

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** Answers each window using the supplied function over the window's text. */
    private PresidioDetector detector(Function<String, String> answer,
                                      AtomicReference<List<String>> windows) throws IOException {
        return detector(answer, windows, 0, new AtomicInteger());
    }

    private PresidioDetector detector(Function<String, String> answer,
                                      AtomicReference<List<String>> windows,
                                      long responseDelayMillis,
                                      AtomicInteger requests) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/analyze", exchange -> {
            requests.incrementAndGet();
            JsonNode request = JSON.readTree(exchange.getRequestBody());
            StringBuilder body = new StringBuilder("[");
            List<String> seen = new java.util.ArrayList<>();
            JsonNode texts = request.path("text");
            for (int index = 0; index < texts.size(); index++) {
                seen.add(texts.get(index).asText());
                body.append(index == 0 ? "" : ",").append(answer.apply(texts.get(index).asText()));
            }
            body.append("]");
            windows.updateAndGet(previous -> {
                List<String> all = new java.util.ArrayList<>(
                        previous == null ? List.of() : previous);
                all.addAll(seen);
                return List.copyOf(all);
            });
            if (responseDelayMillis > 0) {
                try {
                    Thread.sleep(responseDelayMillis);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    exchange.close();
                    return;
                }
            }
            byte[] out = body.toString().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        return new PresidioDetector(new PresidioClient(
                URI.create("http://127.0.0.1:" + server.getAddress().getPort())), PROFILE);
    }

    /** Same wiring as {@link #detector}, but against a caller-supplied profile. */
    private PresidioDetector detectorWithProfile(PresidioProfile profile,
            Function<String, String> answer, AtomicReference<String> requestBody)
            throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/analyze", exchange -> {
            byte[] requestBytes = exchange.getRequestBody().readAllBytes();
            if (requestBody != null) {
                requestBody.set(new String(requestBytes, StandardCharsets.UTF_8));
            }
            JsonNode request = JSON.readTree(requestBytes);
            StringBuilder body = new StringBuilder("[");
            JsonNode texts = request.path("text");
            for (int index = 0; index < texts.size(); index++) {
                body.append(index == 0 ? "" : ",").append(answer.apply(texts.get(index).asText()));
            }
            body.append("]");
            byte[] out = body.toString().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        return new PresidioDetector(new PresidioClient(
                URI.create("http://127.0.0.1:" + server.getAddress().getPort())), profile);
    }

    @Test
    void carriesPresidioCodePointOffsetsThroughUnchanged() throws Exception {
        // An astral emoji is one code point but two Java chars: the offset must not shift.
        String text = "👍 mail x@y.example end";
        AtomicReference<List<String>> windows = new AtomicReference<>();
        PresidioDetector detector = detector(window ->
                "[{\"entity_type\":\"EMAIL_ADDRESS\",\"start\":7,\"end\":18,\"score\":1.0}]",
                windows);

        PresidioScan scan = detector.scan(List.of(new ContentSegment("s", text)));

        assertThat(scan.status()).isEqualTo(DetectionStatus.COMPLETE);
        assertThat(scan.findings()).singleElement().satisfies(finding -> {
            assertThat(finding.start()).isEqualTo(7);
            assertThat(finding.end()).isEqualTo(18);
            assertThat(finding.entity()).isEqualTo("EMAIL_ADDRESS");
        });
        // Code point 7..18 is the email; a UTF-16 reading would be off by one.
        assertThat(text.substring(text.offsetByCodePoints(0, 7), text.offsetByCodePoints(0, 18)))
                .isEqualTo("x@y.example");
    }

    @Test
    void windowsALongSegmentWithOverlapAndDeduplicatesTheSeam() throws Exception {
        String text = "a".repeat(9_000);
        AtomicReference<List<String>> windows = new AtomicReference<>();
        // Every window claims the same absolute value at its own offset zero.
        PresidioDetector detector = detector(window ->
                "[{\"entity_type\":\"URL\",\"start\":0,\"end\":4,\"score\":1.0}]", windows);

        PresidioScan scan = detector.scan(List.of(new ContentSegment("s", text)));

        assertThat(scan.status()).isEqualTo(DetectionStatus.COMPLETE);
        assertThat(windows.get()).hasSize(3);
        assertThat(windows.get().getFirst()).hasSize(PresidioDetector.WINDOW_CODE_POINTS);
        // Windows advance by size minus overlap, so each start is a distinct Finding.
        assertThat(scan.findings()).extracting(PresidioFinding::start)
                .containsExactly(0, 3_840, 7_680);
        assertThat(scan.receivedSegments()).isOne();
        assertThat(scan.inspectedSegments()).isOne();
    }

    @Test
    void scalesTheSharedDeadlineForALargeTurnSplitAcrossAnalyzerBatches() throws Exception {
        AtomicReference<List<String>> windows = new AtomicReference<>();
        AtomicInteger requests = new AtomicInteger();
        PresidioDetector detector = detector(window -> "[]", windows, 600, requests);

        PresidioScan scan = detector.scan(List.of(
                new ContentSegment("large", "a".repeat(70_000))));

        assertThat(requests).hasValue(2);
        assertThat(scan.status()).isEqualTo(DetectionStatus.COMPLETE);
        assertThat(scan.inspectedBytes()).isEqualTo(70_000);
    }

    @Test
    void boundsTheSizeAwareDeadline() {
        assertThat(PresidioDetector.sharedDeadline(0)).isEqualTo(Duration.ofSeconds(1));
        assertThat(PresidioDetector.sharedDeadline(PresidioClient.MAX_REQUEST_BYTES))
                .isEqualTo(Duration.ofSeconds(1));
        assertThat(PresidioDetector.sharedDeadline(PresidioClient.MAX_REQUEST_BYTES + 1L))
                .isEqualTo(Duration.ofSeconds(2));
        assertThat(PresidioDetector.sharedDeadline(Long.MAX_VALUE))
                .isEqualTo(PresidioDetector.MAX_SHARED_DEADLINE);
    }

    @Test
    void ignoresADisabledEntityAndAnAnswerUnderTheApprovedThreshold() throws Exception {
        AtomicReference<List<String>> windows = new AtomicReference<>();
        PresidioDetector detector = detector(window -> """
                [{"entity_type":"PERSON","start":0,"end":4,"score":1.0},\
                {"entity_type":"URL","start":0,"end":4,"score":0.10},\
                {"entity_type":"EMAIL_ADDRESS","start":0,"end":4,"score":0.99}]""", windows);

        PresidioScan scan = detector.scan(List.of(new ContentSegment("s", "abcdef")));

        assertThat(scan.findings()).extracting(PresidioFinding::entity)
                .containsExactly("EMAIL_ADDRESS");
    }

    @Test
    void reportsAGapForAnOffsetOutsideItsWindow() throws Exception {
        AtomicReference<List<String>> windows = new AtomicReference<>();
        PresidioDetector detector = detector(window ->
                "[{\"entity_type\":\"URL\",\"start\":0,\"end\":900,\"score\":1.0}]", windows);

        PresidioScan scan = detector.scan(List.of(new ContentSegment("s", "short")));

        assertThat(scan.status()).isEqualTo(DetectionStatus.INCOMPLETE);
        assertThat(scan.reason()).contains(DetectionReason.BAD_RESPONSE);
        assertThat(scan.findings()).isEmpty();
        assertThat(scan.inspectedBytes()).isZero();
    }

    @Test
    void completesWithoutCallingTheAnalyzerWhenThereIsNothingToInspect() throws Exception {
        AtomicReference<List<String>> windows = new AtomicReference<>();
        PresidioDetector detector = detector(window -> "[]", windows);

        assertThat(detector.scan(List.of()).complete()).isTrue();
        assertThat(detector.scan(List.of(new ContentSegment("s", ""))).complete()).isTrue();
        assertThat(windows.get()).isNull();
    }

    @Test
    void turnsAClientGapIntoAnIncompleteRun() {
        PresidioDetector detector = new PresidioDetector(
                new PresidioClient(URI.create("http://127.0.0.1:1")), PROFILE);

        PresidioScan scan = detector.scan(List.of(new ContentSegment("s", "text")));

        assertThat(scan.complete()).isFalse();
        assertThat(scan.status()).isEqualTo(DetectionStatus.INCOMPLETE);
        assertThat(scan.reason()).isPresent();
        assertThat(detector.profile()).isSameAs(PROFILE);
    }

    @Test
    void keepsFindingsDistinctPerSegment() throws Exception {
        AtomicReference<List<String>> windows = new AtomicReference<>();
        PresidioDetector detector = detector(window ->
                "[{\"entity_type\":\"URL\",\"start\":0,\"end\":4,\"score\":1.0}]", windows);

        PresidioScan scan = detector.scan(List.of(new ContentSegment("one", "abcd"),
                new ContentSegment("two", "abcd")));

        assertThat(scan.findings()).extracting(PresidioFinding::segmentId)
                .containsExactly("one", "two");
    }

    @Test
    void admitsAPerEntityOverrideWhileTheDefaultStillDropsAnotherEntity() throws Exception {
        PresidioDetector detector = detectorWithProfile(PROFILE_WITH_OVERRIDE, window -> """
                [{"entity_type":"IP_ADDRESS","start":0,"end":4,"score":0.6},\
                {"entity_type":"EMAIL_ADDRESS","start":0,"end":4,"score":0.6}]""", null);

        PresidioScan scan = detector.scan(List.of(new ContentSegment("s", "abcdef")));

        assertThat(scan.findings()).extracting(PresidioFinding::entity)
                .containsExactly("IP_ADDRESS");
    }

    @Test
    void anEntityWithNoOverrideFallsBackToTheSelectedThreshold() throws Exception {
        PresidioDetector detector = detectorWithProfile(PROFILE_WITH_OVERRIDE, window -> """
                [{"entity_type":"EMAIL_ADDRESS","start":0,"end":4,"score":0.75}]""", null);

        PresidioScan scan = detector.scan(List.of(new ContentSegment("s", "abcdef")));

        assertThat(scan.findings()).extracting(PresidioFinding::entity)
                .containsExactly("EMAIL_ADDRESS");
    }

    @Test
    void sendsTheMinimumEffectiveThresholdAcrossEntitiesOnTheWire() throws Exception {
        AtomicReference<String> requestBody = new AtomicReference<>();
        PresidioDetector detector = detectorWithProfile(PROFILE_WITH_OVERRIDE, window -> "[]",
                requestBody);

        detector.scan(List.of(new ContentSegment("s", "abcdef")));

        assertThat(requestBody.get()).contains("\"score_threshold\":0.6");
    }
}
