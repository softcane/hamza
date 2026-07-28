package ai.hamza.presidio;

import ai.hamza.policy.DetectionReason;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Bounded in-boundary Presidio Analyzer client. The windows of one managed Turn are
 * sent in ordered batches, each within {@link #MAX_REQUEST_BYTES}, so a large Turn is
 * analyzed across several sequential calls rather than refused whole; at most one call
 * is ever in flight. Every batch and the cumulative response share the one Turn
 * deadline, so exceeding it fails the run safely. The client never retries and never
 * logs request or response content.
 */
public final class PresidioClient {

    public static final Duration CONNECT_TIMEOUT = Duration.ofMillis(200);
    public static final Duration SERVICE_TIMEOUT = Duration.ofMillis(900);
    /** Per-request byte bound. A Turn larger than this is split into several requests. */
    public static final int MAX_REQUEST_BYTES = 65_536;
    public static final int MAX_TURN_RESPONSE_BYTES = 1_048_576;
    public static final int MAX_WINDOW_FINDINGS = 256;

    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient http;
    private final URI analyze;

    public PresidioClient(URI endpoint) {
        this(endpoint, HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT)
                .version(HttpClient.Version.HTTP_1_1).build());
    }

    PresidioClient(URI endpoint, HttpClient http) {
        this.analyze = Objects.requireNonNull(endpoint, "endpoint").resolve("/analyze");
        this.http = Objects.requireNonNull(http, "http");
    }

    /**
     * Analyzes every window, splitting them into ordered batches that each fit within
     * {@link #MAX_REQUEST_BYTES}. Batches are sent sequentially and their per-window
     * answers concatenated in the original order.
     *
     * @param windows   decoded window texts, in order
     * @param entities  the approved entity set to request
     * @param threshold the approved score threshold
     * @param language  the approved profile language
     * @param remaining what is left of the shared Turn deadline
     * @return one Finding list per window, in the same order
     * @throws PresidioGapException on any bound, timeout, or malformed response
     */
    public List<List<RawFinding>> analyze(List<String> windows, List<String> entities,
                                          double threshold, String language,
                                          Duration remaining) {
        Objects.requireNonNull(windows, "windows");
        if (windows.isEmpty()) {
            return List.of();
        }
        if (remaining == null || remaining.isZero() || remaining.isNegative()) {
            throw new PresidioGapException(DetectionReason.TIMEOUT);
        }
        long started = System.nanoTime();
        long responseBytes = 0;
        // The batch body is `overhead + sum(serialized window) + one comma between
        // windows`, exactly, because Jackson writes compact JSON. Sizing batches by
        // that arithmetic serializes each window once instead of re-serializing the
        // whole growing batch per window.
        int overhead = requestBody(List.of(), entities, threshold, language).length;
        List<List<RawFinding>> answers = new ArrayList<>(windows.size());
        int index = 0;
        while (index < windows.size()) {
            List<String> batch = new ArrayList<>();
            long batchBytes = overhead;
            while (index < windows.size()) {
                if (remaining.minusNanos(System.nanoTime() - started).isNegative()) {
                    throw new PresidioGapException(DetectionReason.TIMEOUT);
                }
                long added = serializedBytes(windows.get(index))
                        + (batch.isEmpty() ? 0 : 1);
                if (batchBytes + added > MAX_REQUEST_BYTES) {
                    if (batch.isEmpty()) {
                        // A single window cannot be split, so it alone must fit.
                        throw new PresidioGapException(DetectionReason.INPUT_LIMIT);
                    }
                    break;
                }
                batch.add(windows.get(index));
                batchBytes += added;
                index++;
            }
            Duration left = remaining.minusNanos(System.nanoTime() - started);
            if (left.isZero() || left.isNegative()) {
                throw new PresidioGapException(DetectionReason.TIMEOUT);
            }
            byte[] raw = send(requestBody(batch, entities, threshold, language), left);
            responseBytes += raw.length;
            if (responseBytes > MAX_TURN_RESPONSE_BYTES) {
                throw new PresidioGapException(DetectionReason.OUTPUT_LIMIT);
            }
            answers.addAll(parse(raw, batch.size()));
        }
        return List.copyOf(answers);
    }

    private byte[] send(byte[] body, Duration remaining) {
        Duration timeout = remaining.compareTo(SERVICE_TIMEOUT) < 0 ? remaining : SERVICE_TIMEOUT;
        HttpRequest request = HttpRequest.newBuilder(analyze)
                .header("Content-Type", "application/json")
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();

        HttpResponse<byte[]> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (HttpConnectTimeoutException | ConnectException e) {
            throw new PresidioGapException(DetectionReason.CONNECTION);
        } catch (HttpTimeoutException e) {
            throw new PresidioGapException(DetectionReason.TIMEOUT);
        } catch (IOException e) {
            throw new PresidioGapException(DetectionReason.CONNECTION);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new PresidioGapException(DetectionReason.CANCELLATION);
        }
        if (response.statusCode() != 200) {
            throw new PresidioGapException(DetectionReason.BAD_RESPONSE);
        }
        return response.body();
    }

    private static long serializedBytes(String window) {
        try {
            return JSON.writeValueAsBytes(JSON.getNodeFactory().textNode(window)).length;
        } catch (IOException e) {
            throw new PresidioGapException(DetectionReason.BAD_RESPONSE);
        }
    }

    private static byte[] requestBody(List<String> windows, List<String> entities,
                                      double threshold, String language) {
        ObjectNode root = JSON.createObjectNode();
        ArrayNode texts = root.putArray("text");
        windows.forEach(texts::add);
        root.put("language", language);
        ArrayNode requested = root.putArray("entities");
        entities.forEach(requested::add);
        root.put("score_threshold", threshold);
        try {
            return JSON.writeValueAsBytes(root);
        } catch (IOException e) {
            throw new PresidioGapException(DetectionReason.BAD_RESPONSE);
        }
    }

    private static List<List<RawFinding>> parse(byte[] raw, int windowCount) {
        JsonNode root;
        try {
            root = JSON.readTree(new String(raw, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new PresidioGapException(DetectionReason.BAD_RESPONSE);
        }
        if (!root.isArray()) {
            throw new PresidioGapException(DetectionReason.BAD_RESPONSE);
        }
        // A single window may answer either flat or nested; both read the same when empty.
        if (windowCount == 1 && (root.isEmpty() || !root.get(0).isArray())) {
            return List.of(findings(root));
        }
        if (root.size() != windowCount) {
            throw new PresidioGapException(DetectionReason.BAD_RESPONSE);
        }
        List<List<RawFinding>> byWindow = new ArrayList<>(windowCount);
        for (JsonNode window : root) {
            if (!window.isArray()) {
                throw new PresidioGapException(DetectionReason.BAD_RESPONSE);
            }
            byWindow.add(findings(window));
        }
        return List.copyOf(byWindow);
    }

    private static List<RawFinding> findings(JsonNode array) {
        if (array.size() > MAX_WINDOW_FINDINGS) {
            throw new PresidioGapException(DetectionReason.OUTPUT_LIMIT);
        }
        List<RawFinding> parsed = new ArrayList<>(array.size());
        for (JsonNode finding : array) {
            JsonNode entity = finding.path("entity_type");
            JsonNode start = finding.path("start");
            JsonNode end = finding.path("end");
            JsonNode score = finding.path("score");
            if (!entity.isTextual() || !start.isInt() || !end.isInt() || !score.isNumber()) {
                throw new PresidioGapException(DetectionReason.BAD_RESPONSE);
            }
            parsed.add(new RawFinding(entity.asText(), start.asInt(), end.asInt(),
                    score.asDouble()));
        }
        return List.copyOf(parsed);
    }

    /** One transient Finding as reported inside a single window. */
    public record RawFinding(String entity, int start, int end, double score) { }
}
