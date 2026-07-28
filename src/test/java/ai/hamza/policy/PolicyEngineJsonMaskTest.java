package ai.hamza.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import ai.hamza.presidio.PresidioClient;
import ai.hamza.presidio.PresidioDetector;
import ai.hamza.presidio.PresidioProfile;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * The standard route masks the body as it sits on the wire, so a detector span that is
 * not JSON-aware can otherwise splice a Placeholder across a quote and destroy the
 * request — the Provider then rejects the whole Turn with "not valid JSON". These tests
 * hold the two invariants that make that impossible: valid JSON in, valid JSON out; and
 * a value inside a JSON string really is masked, never quietly downgraded.
 */
class PolicyEngineJsonMaskTest {

    private static final PresidioProfile PROFILE =
            PresidioProfile.load(Path.of("detector/presidio/approved-profile.json"));
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String AWS_KEY = "AKIAABCDEFGHIJKLMNOP";
    private static final String EMAIL = "ops@example.com";

    /** A realistic compact Agent Turn: no whitespace for a URL span to stop at. */
    private static final String BODY = "{\"model\":\"claude-opus-4\",\"max_tokens\":1024,"
            + "\"messages\":[{\"role\":\"user\",\"content\":\"deploy with "
            + "https://ops.example.test/run?key=" + AWS_KEY + "\"},"
            + "{\"role\":\"user\",\"content\":\"then mail " + EMAIL + " about it\"}]}";

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    /** Presidio stub answering one window with the given findings, verbatim. */
    private PresidioDetector presidio(String findings) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/analyze", exchange -> {
            byte[] out = findings.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        return new PresidioDetector(new PresidioClient(
                URI.create("http://127.0.0.1:" + server.getAddress().getPort())), PROFILE);
    }

    private static String finding(String entity, int start, int end) {
        return "{\"entity_type\":\"" + entity + "\",\"start\":" + start + ",\"end\":" + end
                + ",\"score\":0.99}";
    }

    private PolicyEngine engine(Map<String, Action> rules, PresidioDetector presidio) {
        return new PolicyEngine(new SecretDetector(), new Masker(), Action.FLAG, rules,
                null, 30, presidio);
    }

    private static String masked(PolicyResult result) {
        return new String(result.maskedBody().orElseThrow(), StandardCharsets.UTF_8);
    }

    private static void parses(String body) {
        assertThatCode(() -> JSON.readTree(body)).doesNotThrowAnyException();
    }

    /**
     * The live failure: Presidio's URL recognizer runs to the next whitespace, and compact
     * JSON has none, so the span swallows {@code ","role":"user"...} — spliced raw, the body
     * stops being JSON. The span must be clamped to the string value it started in.
     */
    @Test
    void aSpanCrossingAJsonBoundaryStillLeavesValidJson() throws Exception {
        int start = BODY.indexOf("https://");
        int end = BODY.indexOf("about it");           // far past the closing quote
        assertThat(BODY.substring(start, end)).contains("\"},{\"role\"");   // it really crosses

        PolicyResult result = engine(Map.of("url", Action.MASK), presidio(
                "[" + finding("URL", start, end) + "]")).evaluate(bytes(BODY));

        assertThat(result.isMask()).isTrue();
        String body = masked(result);
        parses(body);
        // The structure the span ran through is untouched, and the value it started in is gone.
        assertThat(JSON.readTree(body).path("messages").path(1).path("content").asText())
                .isEqualTo("then mail " + EMAIL + " about it");
        assertThat(JSON.readTree(body).path("model").asText()).isEqualTo("claude-opus-4");
        assertThat(body).containsPattern("<PII_\\d+>").doesNotContain("ops.example.test");
    }

    /**
     * The requirement behind the fix: a value that sits inside one JSON string is masked —
     * both a Presidio entity and a rulepack secret, in the same body, on the same pass.
     */
    @Test
    void anEmailAndAnAwsKeyInOneCompactBodyAreBothMasked() throws Exception {
        int start = BODY.indexOf(EMAIL);
        PolicyResult result = engine(
                Map.of("email-address", Action.MASK, "aws-access-token", Action.MASK),
                presidio("[" + finding("EMAIL_ADDRESS", start, start + EMAIL.length()) + "]"))
                .evaluate(bytes(BODY));

        assertThat(result.isMask()).isTrue();
        String body = masked(result);
        parses(body);
        assertThat(body).doesNotContain(EMAIL).doesNotContain(AWS_KEY);
        assertThat(body).containsPattern("<EMAIL_\\d+>").containsPattern("<SECRET_\\d+>");
        // Both Findings kept their Mask; neither was silently downgraded to FLAG.
        assertThat(result.findings())
                .filteredOn(f -> f.rule().equals("email-address") || f.rule().equals("aws-access-token"))
                .extracting(Finding::action)
                .containsOnly(Action.MASK);
    }

    /**
     * A wide span that covers a second, narrower one must not swallow it: the AWS key
     * inside the URL is masked in its own right, not merely deleted along with the URL.
     */
    @Test
    void aWideSpanDoesNotSuppressTheSecretInsideIt() throws Exception {
        int start = BODY.indexOf("https://");
        int end = BODY.indexOf("about it");
        PolicyResult result = engine(
                Map.of("url", Action.MASK, "aws-access-token", Action.MASK),
                presidio("[" + finding("URL", start, end) + "]")).evaluate(bytes(BODY));

        String body = masked(result);
        parses(body);
        assertThat(body).doesNotContain(AWS_KEY);
        assertThat(body).containsPattern("<PII_\\d+>").containsPattern("<SECRET_\\d+>");
    }

    /**
     * A span may not be cut inside a {@code \"} escape either: half an escape is as
     * unparseable as an unbalanced quote.
     */
    @Test
    void aSpanStartingInsideAnEscapeStillLeavesValidJson() throws Exception {
        String escaped = "{\"model\":\"claude-opus-4\",\"messages\":[{\"role\":\"user\","
                + "\"content\":\"say \\\"hi\\\" then mail " + EMAIL + "\"}]}";
        int start = escaped.indexOf("\\\"hi") + 1;    // inside the escape, on the quote
        int end = escaped.indexOf(EMAIL) + EMAIL.length();

        PolicyResult result = engine(Map.of("url", Action.MASK), presidio(
                "[" + finding("URL", start, end) + "]")).evaluate(bytes(escaped));

        assertThat(result.isMask()).isTrue();
        String body = masked(result);
        parses(body);
        // The escape survived intact: the span was clamped forward to the next character.
        assertThat(JSON.readTree(body).path("messages").path(0).path("content").asText())
                .startsWith("say \"").doesNotContain(EMAIL);
    }

    /**
     * A span that reaches no string value at all — here the top-level {@code max_tokens}
     * number — has nothing that can be replaced without rewriting the wire shape. It
     * degrades to a FLAG the Record shows, and the body is left alone.
     */
    @Test
    void aSpanOverNoStringValueDegradesToFlagInsteadOfCorruptingTheBody() throws Exception {
        int start = BODY.indexOf("1024");
        PolicyResult result = engine(Map.of("url", Action.MASK), presidio(
                "[" + finding("URL", start, start + 4) + "]")).evaluate(bytes(BODY));

        assertThat(result.effectiveAction()).isEqualTo(Action.FLAG);
        assertThat(result.maskedBody()).isEmpty();
        assertThat(result.findings()).filteredOn(f -> f.rule().equals("url"))
                .extracting(Finding::action).containsOnly(Action.FLAG);
    }

    /**
     * The last line of defence, with a deliberately broken Masker: a masked body that no
     * longer parses is never egressed. It degrades to the unmasked body under a loud
     * {@code mask-unverified} Finding, and blocks when that rule enforces.
     */
    @Test
    void aBodyThatNoLongerParsesIsNeverEgressed() {
        Masker broken = new Masker() {
            @Override
            public String mask(String text, List<Replacement> replacements) {
                return text.substring(0, text.length() / 2);      // truncated: not JSON
            }
        };

        PolicyEngine flagging = new PolicyEngine(new SecretDetector(), broken, Action.FLAG,
                Map.of("aws-access-token", Action.MASK));
        PolicyResult flagged = flagging.evaluate(bytes(BODY));
        assertThat(flagged.effectiveAction()).isEqualTo(Action.FLAG);
        assertThat(flagged.maskedBody()).isEmpty();
        assertThat(flagged.findings()).extracting(Finding::rule)
                .contains(PolicyEngine.MASK_UNVERIFIED_RULE);
        assertThat(flagged.findings()).extracting(Finding::action).doesNotContain(Action.MASK);

        PolicyEngine enforcing = new PolicyEngine(new SecretDetector(), broken, Action.FLAG,
                Map.of("aws-access-token", Action.MASK,
                        PolicyEngine.MASK_UNVERIFIED_RULE, Action.BLOCK));
        PolicyResult blocked = enforcing.evaluate(bytes(BODY));
        assertThat(blocked.isBlock()).isTrue();
        assertThat(blocked.blockingRules()).contains(PolicyEngine.MASK_UNVERIFIED_RULE);
        assertThat(blocked.maskedBody()).isEmpty();
    }

    /** A body that is not JSON has no structure to protect and is still masked. */
    @Test
    void aNonJsonBodyIsStillMasked() {
        PolicyEngine engine = new PolicyEngine(new SecretDetector(), new Masker(), Action.MASK,
                Map.of());
        PolicyResult result = engine.evaluate(bytes("deploy with " + AWS_KEY + " today"));

        assertThat(result.isMask()).isTrue();
        assertThat(masked(result)).doesNotContain(AWS_KEY).containsPattern("<SECRET_\\d+>");
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
