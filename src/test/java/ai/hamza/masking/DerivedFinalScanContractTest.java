package ai.hamza.masking;

import ai.hamza.adapter.AnthropicMessagesAdapter;
import ai.hamza.adapter.OpenAiResponsesAdapter;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.policy.Action;
import ai.hamza.policy.DetectionStatus;
import ai.hamza.policy.Masker;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.SecretDetector;
import ai.hamza.presidio.PresidioClient;
import ai.hamza.presidio.PresidioDetector;
import ai.hamza.presidio.PresidioProfile;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DerivedFinalScanContractTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void openAiSecretAndEdmFlowProducesOneCleanRescannedDerivedBody() {
        byte[] source = ("{\"model\":\"gpt-5-codex\",\"input\":\"customer "
                + MaskingTestFixture.EMAIL + " used " + MaskingTestFixture.SECRET + "\"}")
                .getBytes(StandardCharsets.UTF_8);

        MaskContinuationResult result = MaskingTestFixture.service()
                .apply("scope-1", new OpenAiResponsesAdapter(), source);

        assertThat(result).isInstanceOf(MaskContinuationResult.Masked.class);
        MaskContinuationResult.Masked masked = (MaskContinuationResult.Masked) result;
        String derived = new String(masked.derivedBody(), StandardCharsets.UTF_8);
        assertThat(derived).contains("<EMAIL_", "<SECRET_")
                .doesNotContain(MaskingTestFixture.EMAIL, MaskingTestFixture.SECRET);
        assertThat(masked.finalRuns()).allMatch(run ->
                run.status() == DetectionStatus.COMPLETE && run.findings().isEmpty());
    }

    @Test
    void anthropicUsesTheSameCompleteFinalRescan() {
        byte[] source = ("{\"model\":\"claude-haiku-4-5-20251001\",\"max_tokens\":256,"
                + "\"messages\":[{\"role\":\"user\",\"content\":\"customer "
                + MaskingTestFixture.EMAIL + " used " + MaskingTestFixture.SECRET + "\"}]}")
                .getBytes(StandardCharsets.UTF_8);

        MaskContinuationResult result = MaskingTestFixture.service()
                .apply("scope-2", new AnthropicMessagesAdapter(), source);

        assertThat(result).isInstanceOf(MaskContinuationResult.Masked.class);
        String derived = new String(((MaskContinuationResult.Masked) result).derivedBody(),
                StandardCharsets.UTF_8);
        assertThat(derived).contains("<EMAIL_", "<SECRET_")
                .doesNotContain(MaskingTestFixture.EMAIL, MaskingTestFixture.SECRET);
    }

    @Test
    void flagOnlyPresidioResidueDoesNotRejectAnOtherwiseCleanDerivedTurn()
            throws Exception {
        String email = "priya.fixture@example.com";
        String url = "https://example.invalid/docs";
        HttpServer analyzer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        analyzer.createContext("/analyze", exchange -> {
            String text = JSON.readTree(exchange.getRequestBody()).path("text").path(0).asText();
            ArrayNode findings = JSON.createArrayNode();
            addFinding(findings, text, email, "EMAIL_ADDRESS");
            addFinding(findings, text, url, "URL");
            byte[] response = JSON.writeValueAsBytes(findings);
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        analyzer.start();
        try {
            PresidioProfile profile = PresidioProfile.load(
                    Path.of("detector/presidio/approved-profile.json"));
            PresidioDetector presidio = new PresidioDetector(new PresidioClient(URI.create(
                    "http://127.0.0.1:" + analyzer.getAddress().getPort())), profile);
            SecretDetector secrets = new SecretDetector();
            EdmMatcher edm = new EdmMatcher(List.of(), List.of(), 10);
            PolicyEngine policy = new PolicyEngine(secrets, new Masker(), Action.FLAG,
                    Map.of("email-address", Action.MASK), edm, 10);
            MaskScopeStore scopes = new MaskScopeStore();
            MaskContinuationService service = new MaskContinuationService(
                    new MaskDetectionService(secrets, edm, policy, presidio),
                    new MaskPlanner(scopes), scopes);
            byte[] source = ("{\"model\":\"gpt-5-codex\",\"input\":\"mail "
                    + email + " docs " + url + "\"}").getBytes(StandardCharsets.UTF_8);

            assertThat(service.apply("scope-flag-residue", new OpenAiResponsesAdapter(), source))
                    .isInstanceOfSatisfying(MaskContinuationResult.Masked.class, masked -> {
                        String derived = new String(masked.derivedBody(),
                                StandardCharsets.UTF_8);
                        assertThat(derived).doesNotContain(email).contains(url, "<EMAIL_");
                        assertThat(masked.finalRuns().stream()
                                .filter(run -> run.detectorId().equals("presidio"))
                                .flatMap(run -> run.findings().stream()))
                                .singleElement().satisfies(finding -> {
                                    assertThat(finding.rule()).isEqualTo("url");
                                    assertThat(finding.action()).isEqualTo(Action.FLAG);
                                });
                    });
        } finally {
            analyzer.stop(0);
        }
    }

    private static void addFinding(ArrayNode findings, String text, String value,
                                   String entity) {
        int start = text.indexOf(value);
        if (start >= 0) {
            findings.addObject().put("entity_type", entity).put("start", start)
                    .put("end", start + value.length()).put("score", 1.0);
        }
    }

    @Test
    void malformedAndIncompleteSourceDetectionFailClosed() {
        MaskContinuationService service = MaskingTestFixture.service();
        assertThat(service.apply("scope-3", new OpenAiResponsesAdapter(), "{}".getBytes()))
                .isEqualTo(new MaskContinuationResult.Failed(
                        MaskContinuationResult.Reason.ADAPTER_EXTRACTION,
                        java.util.List.of()));

        var edm = MaskingTestFixture.matcher(1);
        var secrets = new ai.hamza.policy.SecretDetector();
        var policy = new ai.hamza.policy.PolicyEngine(secrets, new ai.hamza.policy.Masker(),
                ai.hamza.policy.Action.MASK, java.util.Map.of(), edm, 1);
        MaskScopeStore scopes = new MaskScopeStore();
        MaskContinuationService bounded = new MaskContinuationService(
                new MaskDetectionService(secrets, edm, policy), new MaskPlanner(scopes), scopes);
        byte[] source = ("{\"model\":\"gpt-5-codex\",\"input\":\"one two "
                + MaskingTestFixture.EMAIL + "\"}").getBytes(StandardCharsets.UTF_8);

        assertThat(bounded.apply("scope-4", new OpenAiResponsesAdapter(), source))
                .isInstanceOfSatisfying(MaskContinuationResult.Failed.class,
                        failed -> assertThat(failed.reason())
                                .isEqualTo(MaskContinuationResult.Reason.DETECTION_INCOMPLETE));
    }

    @Test
    void bodyBoundsBlockingPolicyAndFlagOnlyTurnsFailOrSkipWithoutEgress() {
        MaskContinuationService service = MaskingTestFixture.service();
        assertThat(service.apply("scope-5", new OpenAiResponsesAdapter(), null))
                .isInstanceOfSatisfying(MaskContinuationResult.Failed.class,
                        failed -> assertThat(failed.reason())
                                .isEqualTo(MaskContinuationResult.Reason.BODY_LIMIT));
        assertThat(service.apply("scope-5", new OpenAiResponsesAdapter(),
                new byte[MaskContinuationService.DEFAULT_MAX_BODY_BYTES + 1]))
                .isInstanceOf(MaskContinuationResult.Failed.class);

        var emptyEdm = new ai.hamza.edm.EdmMatcher(java.util.List.of(),
                java.util.List.of(), 10);
        var secrets = new ai.hamza.policy.SecretDetector();
        var flagPolicy = new ai.hamza.policy.PolicyEngine(secrets,
                new ai.hamza.policy.Masker(), ai.hamza.policy.Action.FLAG,
                java.util.Map.of(), emptyEdm, 1);
        MaskScopeStore flagScopes = new MaskScopeStore();
        MaskContinuationService flagOnly = new MaskContinuationService(
                new MaskDetectionService(secrets, emptyEdm, flagPolicy),
                new MaskPlanner(flagScopes), flagScopes);
        byte[] source = ("{\"model\":\"gpt-5-codex\",\"input\":\""
                + MaskingTestFixture.SECRET + "\"}").getBytes(StandardCharsets.UTF_8);
        assertThat(flagOnly.apply("scope-6", new OpenAiResponsesAdapter(), source))
                .isInstanceOf(MaskContinuationResult.NotRequired.class);

        var blockPolicy = new ai.hamza.policy.PolicyEngine(secrets,
                new ai.hamza.policy.Masker(), ai.hamza.policy.Action.BLOCK,
                java.util.Map.of(), emptyEdm, 1);
        MaskScopeStore blockScopes = new MaskScopeStore();
        MaskContinuationService blocked = new MaskContinuationService(
                new MaskDetectionService(secrets, emptyEdm, blockPolicy),
                new MaskPlanner(blockScopes), blockScopes);
        assertThat(blocked.apply("scope-7", new OpenAiResponsesAdapter(), source))
                .isInstanceOfSatisfying(MaskContinuationResult.Failed.class,
                        failed -> assertThat(failed.reason())
                                .isEqualTo(MaskContinuationResult.Reason.BLOCKING_FINDING));
    }
}
