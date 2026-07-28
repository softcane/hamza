package ai.hamza.presidio;

import ai.hamza.policy.DetectionReason;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PresidioClientTest {

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private PresidioClient serving(int status, String body, AtomicReference<String> captured,
                                   AtomicInteger calls) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/analyze", exchange -> {
            calls.incrementAndGet();
            captured.set(new String(exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8));
            byte[] out = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        return new PresidioClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort()));
    }

    private PresidioClient serving(int status, String body) throws IOException {
        return serving(status, body, new AtomicReference<>(), new AtomicInteger());
    }

    /** Replies with one empty Finding list per window in the request, counting calls. */
    private PresidioClient perWindow(AtomicInteger calls) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/analyze", exchange -> {
            calls.incrementAndGet();
            String request = new String(exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8);
            int windows = new com.fasterxml.jackson.databind.ObjectMapper()
                    .readTree(request).path("text").size();
            byte[] out = ("[" + "[],".repeat(windows)).replaceAll(",$", "")
                    .concat("]").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        return new PresidioClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort()));
    }

    @Test
    void splitsALargeTurnIntoSeveralOrderedRequestsThatEachFitTheByteBound() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        PresidioClient client = perWindow(calls);
        // Each window is ~8 KiB, so several must not share one 64 KiB request; 40 windows
        // is well over the old whole-Turn cap the analyzer used to refuse outright.
        List<String> windows = new java.util.ArrayList<>();
        for (int index = 0; index < 40; index++) {
            windows.add("w" + index + "-" + "x".repeat(8_000));
        }

        List<List<PresidioClient.RawFinding>> answers = client.analyze(windows,
                List.of("EMAIL_ADDRESS"), 0.75, "en", Duration.ofMillis(900));

        assertThat(answers).hasSize(40);
        assertThat(answers).allSatisfy(list -> assertThat(list).isEmpty());
        assertThat(calls.get()).isGreaterThan(1);
    }

    @Test
    void sendsTheApprovedProfileAndReadsOneFindingListPerWindow() throws Exception {
        AtomicReference<String> captured = new AtomicReference<>();
        PresidioClient client = serving(200,
                "[[{\"entity_type\":\"EMAIL_ADDRESS\",\"start\":5,\"end\":9,\"score\":1.0}],[]]",
                captured, new AtomicInteger());

        List<List<PresidioClient.RawFinding>> answers = client.analyze(
                List.of("first", "second"), List.of("EMAIL_ADDRESS"), 0.75, "en",
                Duration.ofMillis(900));

        assertThat(answers).hasSize(2);
        assertThat(answers.get(0)).containsExactly(
                new PresidioClient.RawFinding("EMAIL_ADDRESS", 5, 9, 1.0));
        assertThat(answers.get(1)).isEmpty();
        assertThat(captured.get()).contains("\"score_threshold\":0.75", "\"language\":\"en\"",
                "\"entities\":[\"EMAIL_ADDRESS\"]", "\"text\":[\"first\",\"second\"]");
    }

    @Test
    void acceptsAFlatAnswerForASingleWindow() throws Exception {
        PresidioClient client = serving(200,
                "[{\"entity_type\":\"URL\",\"start\":0,\"end\":3,\"score\":0.9}]");

        List<List<PresidioClient.RawFinding>> answers = client.analyze(List.of("one"),
                List.of("URL"), 0.5, "en", Duration.ofMillis(900));

        assertThat(answers).hasSize(1);
        assertThat(answers.getFirst()).hasSize(1);
    }

    @Test
    void treatsAnEmptyAnswerForOneWindowAsZeroFindings() throws Exception {
        PresidioClient client = serving(200, "[]");

        assertThat(client.analyze(List.of("one"), List.of("URL"), 0.5, "en",
                Duration.ofMillis(900))).containsExactly(List.of());
    }

    @Test
    void neverCallsTheAnalyzerWithoutWindowsOrDeadline() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        PresidioClient client = serving(200, "[]", new AtomicReference<>(), calls);

        assertThat(client.analyze(List.of(), List.of("URL"), 0.5, "en",
                Duration.ofMillis(900))).isEmpty();
        assertThatThrownBy(() -> client.analyze(List.of("one"), List.of("URL"), 0.5, "en",
                Duration.ZERO)).isInstanceOf(PresidioGapException.class)
                .extracting(gap -> ((PresidioGapException) gap).reason())
                .isEqualTo(DetectionReason.TIMEOUT);
        assertThat(calls).hasValue(0);
    }

    @Test
    void reportsABoundedGapForEveryUnusableAnswer() throws Exception {
        assertReason(serving(500, "[]"), DetectionReason.BAD_RESPONSE);
        assertReason(serving(200, "{\"not\":\"an array\"}"), DetectionReason.BAD_RESPONSE);
        assertReason(serving(200, "not json"), DetectionReason.BAD_RESPONSE);
        assertReason(serving(200, "[[],[]]"), DetectionReason.BAD_RESPONSE);
        assertReason(serving(200, "[[{\"entity_type\":\"URL\",\"start\":\"x\",\"end\":3,"
                + "\"score\":0.9}]]"), DetectionReason.BAD_RESPONSE);
    }

    @Test
    void refusesAWindowAnswerOverTheFindingCap() throws Exception {
        StringBuilder body = new StringBuilder("[[");
        for (int index = 0; index <= PresidioClient.MAX_WINDOW_FINDINGS; index++) {
            body.append(index == 0 ? "" : ",")
                    .append("{\"entity_type\":\"URL\",\"start\":0,\"end\":1,\"score\":1.0}");
        }
        body.append("]]");

        assertReason(serving(200, body.toString()), DetectionReason.OUTPUT_LIMIT);
    }

    /**
     * M1's chosen behavior for the volume risk: a lower per-entity wire threshold can
     * make the Analyzer return more low-score spans for every requested entity, not
     * only the lowered ones. Rather than raise {@code MAX_WINDOW_FINDINGS} on an
     * unmeasured guess, this milestone keeps the existing cap and accepts the fail-closed
     * {@code OUTPUT_LIMIT} gap as designed behavior; a scan that hits it reports
     * INCOMPLETE and the managed Turn fails closed to a Block.
     */
    @Test
    void refusesAWindowAnswerOverTheFindingCapAtAMinimumWireThreshold() throws Exception {
        StringBuilder body = new StringBuilder("[[");
        for (int index = 0; index <= PresidioClient.MAX_WINDOW_FINDINGS; index++) {
            body.append(index == 0 ? "" : ",")
                    .append("{\"entity_type\":\"URL\",\"start\":0,\"end\":1,\"score\":0.05}");
        }
        body.append("]]");
        PresidioClient client = serving(200, body.toString());

        assertThatThrownBy(() -> client.analyze(List.of("one"), List.of("URL"), 0.0, "en",
                Duration.ofMillis(900)))
                .isInstanceOf(PresidioGapException.class)
                .extracting(gap -> ((PresidioGapException) gap).reason())
                .isEqualTo(DetectionReason.OUTPUT_LIMIT);
    }

    @Test
    void refusesARequestOverTheTurnByteBound() throws Exception {
        PresidioClient client = serving(200, "[]");
        String oversize = "x".repeat(PresidioClient.MAX_REQUEST_BYTES);

        assertThatThrownBy(() -> client.analyze(List.of(oversize), List.of("URL"), 0.5, "en",
                Duration.ofMillis(900)))
                .isInstanceOf(PresidioGapException.class)
                .extracting(gap -> ((PresidioGapException) gap).reason())
                .isEqualTo(DetectionReason.INPUT_LIMIT);
    }

    @Test
    void reportsAConnectionGapWhenNothingIsListening() {
        PresidioClient client = new PresidioClient(URI.create("http://127.0.0.1:1"));

        assertThatThrownBy(() -> client.analyze(List.of("one"), List.of("URL"), 0.5, "en",
                Duration.ofMillis(900)))
                .isInstanceOf(PresidioGapException.class)
                .extracting(gap -> ((PresidioGapException) gap).reason())
                .isIn(DetectionReason.CONNECTION, DetectionReason.TIMEOUT);
    }

    @Test
    void reportsATimeoutGapWhenTheAnalyzerIsTooSlow() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/analyze", exchange -> {
            try {
                Thread.sleep(400);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.sendResponseHeaders(200, 2);
            exchange.getResponseBody().write("[]".getBytes(StandardCharsets.UTF_8));
            exchange.close();
        });
        server.start();
        PresidioClient client = new PresidioClient(
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()));

        assertThatThrownBy(() -> client.analyze(List.of("one"), List.of("URL"), 0.5, "en",
                Duration.ofMillis(50)))
                .isInstanceOf(PresidioGapException.class)
                .extracting(gap -> ((PresidioGapException) gap).reason())
                .isEqualTo(DetectionReason.TIMEOUT);
    }

    @Test
    void carriesOnlyABoundedReasonCode() {
        PresidioGapException gap = new PresidioGapException(DetectionReason.OUTPUT_LIMIT);

        assertThat(gap.reason()).isEqualTo(DetectionReason.OUTPUT_LIMIT);
        assertThat(gap.getMessage()).isEqualTo("OUTPUT_LIMIT");
    }

    private static void assertReason(PresidioClient client, DetectionReason expected) {
        assertThatThrownBy(() -> client.analyze(List.of("one"), List.of("URL"), 0.5, "en",
                Duration.ofMillis(900)))
                .isInstanceOf(PresidioGapException.class)
                .extracting(gap -> ((PresidioGapException) gap).reason())
                .isEqualTo(expected);
    }
}
