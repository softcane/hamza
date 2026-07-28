package ai.hamza.masking;

import ai.hamza.adapter.ContentSegment;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.policy.Action;
import ai.hamza.policy.DetectionReason;
import ai.hamza.policy.DetectionRun;
import ai.hamza.policy.DetectionStatus;
import ai.hamza.policy.Masker;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.SecretDetector;
import ai.hamza.presidio.PresidioClient;
import ai.hamza.presidio.PresidioDetector;
import ai.hamza.presidio.PresidioProfile;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The registered-detector contract for Presidio inside the common detection service. */
class MaskDetectionPresidioTest {

    private static final PresidioProfile PROFILE =
            PresidioProfile.load(Path.of("detector/presidio/approved-profile.json"));
    private static final String EMAIL_FINDING =
            "[{\"entity_type\":\"EMAIL_ADDRESS\",\"start\":0,\"end\":4,\"score\":1.0}]";

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private PresidioDetector detector(String answer) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/analyze", exchange -> {
            byte[] out = answer.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        return new PresidioDetector(new PresidioClient(
                URI.create("http://127.0.0.1:" + server.getAddress().getPort())), PROFILE);
    }

    private static MaskDetectionService service(PresidioDetector presidio, Action emailAction) {
        SecretDetector secrets = new SecretDetector();
        EdmMatcher edm = new EdmMatcher(List.of(), List.of(), 50_000);
        PolicyEngine policy = new PolicyEngine(secrets, new Masker(), Action.FLAG,
                Map.of("email-address", emailAction), edm, 10);
        return new MaskDetectionService(secrets, edm, policy, presidio);
    }

    private static DetectionRun run(MaskDetection detection, String detectorId) {
        return detection.runs().stream()
                .filter(value -> value.detectorId().equals(detectorId))
                .findFirst().orElseThrow();
    }

    @Test
    void registersPresidioOnlyWhenItIsConfigured() throws Exception {
        MaskDetection without = service(null, Action.MASK)
                .scan(List.of(new ContentSegment("s", "abcdef")));
        assertThat(without.runs()).extracting(DetectionRun::detectorId)
                .containsExactly("secret", "edm");

        MaskDetection with = service(detector(EMAIL_FINDING), Action.MASK)
                .scan(List.of(new ContentSegment("s", "abcdef")));
        assertThat(with.runs()).extracting(DetectionRun::detectorId)
                .containsExactly("secret", "edm", "presidio");
    }

    @Test
    void anEnabledPresidioRuleWithAnExactSpanBecomesAMaskCandidate() throws Exception {
        MaskDetection detection = service(detector(EMAIL_FINDING), Action.MASK)
                .scan(List.of(new ContentSegment("s", "abcdef")));

        assertThat(detection.complete()).isTrue();
        assertThat(detection.candidates()).singleElement().satisfies(candidate -> {
            assertThat(candidate.detectorId()).isEqualTo("presidio");
            assertThat(candidate.rule()).isEqualTo("email-address");
            assertThat(candidate.family()).isEqualTo(PlaceholderFamily.EMAIL);
            assertThat(candidate.start()).isZero();
            assertThat(candidate.end()).isEqualTo(4);
        });
        assertThat(detection.findings()).extracting(finding -> finding.detector()
                + ':' + finding.rule()).contains("presidio:email-address");
        assertThat(run(detection, "presidio").detectorVersion())
                .isEqualTo("presidio:broad-pii-en:v1");
    }

    @Test
    void aBlockingPresidioRuleStopsTheManagedTurn() throws Exception {
        MaskDetection detection = service(detector(EMAIL_FINDING), Action.BLOCK)
                .scan(List.of(new ContentSegment("s", "abcdef")));

        assertThat(detection.blockingRules()).containsExactly("email-address");
        assertThat(detection.candidates()).isEmpty();
    }

    @Test
    void anObserveOnlyPresidioRuleNeverMasks() throws Exception {
        MaskDetection detection = service(detector(EMAIL_FINDING), Action.FLAG)
                .scan(List.of(new ContentSegment("s", "abcdef")));

        assertThat(detection.candidates()).isEmpty();
        assertThat(detection.blockingRules()).isEmpty();
        assertThat(run(detection, "presidio").findings()).singleElement()
                .satisfies(finding -> assertThat(finding.action()).isEqualTo(Action.FLAG));
    }

    @Test
    void anIncompletePresidioRunMakesTheWholeDetectionIncomplete() {
        PresidioDetector unreachable = new PresidioDetector(
                new PresidioClient(URI.create("http://127.0.0.1:1")), PROFILE);

        MaskDetection detection = service(unreachable, Action.MASK)
                .scan(List.of(new ContentSegment("s", "abcdef")));

        assertThat(detection.complete()).isFalse();
        assertThat(run(detection, "presidio").status()).isEqualTo(DetectionStatus.INCOMPLETE);
        assertThat(run(detection, "secret").status()).isEqualTo(DetectionStatus.COMPLETE);
    }

    @Test
    void anOverBoundTurnReportsAnInputLimitGapForEveryRegisteredDetector() throws Exception {
        MaskDetectionService service = service(detector(EMAIL_FINDING), Action.MASK);

        MaskDetection detection = service.scan(List.of(
                new ContentSegment("s", "x".repeat(MaskContinuationService.DEFAULT_MAX_BODY_BYTES + 1))));

        assertThat(detection.complete()).isFalse();
        assertThat(detection.runs()).hasSize(3).allSatisfy(value -> {
            assertThat(value.status()).isEqualTo(DetectionStatus.INCOMPLETE);
            assertThat(value.reason()).contains(DetectionReason.INPUT_LIMIT);
            assertThat(value.inspectedBytes()).isZero();
        });
        assertThat(detection.candidates()).isEmpty();
    }
}
