package ai.hamza.presidio;

import ai.hamza.adapter.AnthropicMessagesAdapter;
import ai.hamza.adapter.OpenAiResponsesAdapter;
import ai.hamza.adapter.ProviderAdapter;
import ai.hamza.edm.EdmMatcher;
import ai.hamza.edm.Fingerprinter;
import ai.hamza.edm.RegistryRecipe;
import ai.hamza.edm.ReplacementKind;
import ai.hamza.edm.TypedRegistry;
import ai.hamza.masking.MaskContinuationResult;
import ai.hamza.masking.MaskContinuationService;
import ai.hamza.masking.MaskDetectionService;
import ai.hamza.masking.MaskPlanner;
import ai.hamza.masking.MaskScopeStore;
import ai.hamza.policy.Action;
import ai.hamza.policy.DetectionRun;
import ai.hamza.policy.DetectionStatus;
import ai.hamza.policy.Masker;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.SecretDetector;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Deterministic M4 gate. Runs the pinned in-boundary Analyzer and proves the whole
 * managed flow for both Provider formats: detect, mask, rescan, and release only a
 * DERIVED body. Every fixture is fake. No Provider quota is spent.
 */
class PresidioMaskProviderGateIT {

    private static final String IMAGE = "ghcr.io/data-privacy-stack/presidio-analyzer@sha256:"
            + "286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9";
    private static final int PORT = 13_100;
    private static final ObjectMapper JSON = new ObjectMapper();

    // Fake fixtures only: reserved domain, RFC 5737 range, reserved 555-01xx number,
    // a Luhn-valid test card, and a fake AWS-shaped key.
    private static final String PII_EMAIL = "priya.fixture@example.com";
    private static final String CARD = "4111111111111111";
    private static final String IP = "192.0.2.44";
    private static final String PHONE = "+1 202-555-0143";
    private static final String FAKE_SECRET = "AKIAABCDEFGHIJKLMNOP";
    private static final String EDM_EMAIL = "anna.fixture@example.invalid";
    /** M3 disabled PERSON, so this fake name must survive unmasked. */
    private static final String PERSON = "Anna Example";

    private static final byte[] SALT = "01234567890123456789012345678901"
            .getBytes(StandardCharsets.UTF_8);
    private static final Path ROOT = Path.of("").toAbsolutePath().normalize();
    private static final Path DETECTOR = ROOT.resolve("detector/presidio");
    private static final String PROJECT = "hamza-presidio-provider-"
            + ProcessHandle.current().pid();
    private static final List<String> COMPOSE = List.of("docker", "compose", "-p", PROJECT,
            "-f", DETECTOR.resolve("compose-integration.yaml").toString());

    @BeforeAll
    static void startAnalyzer() throws Exception {
        required(Duration.ofMinutes(3), append(COMPOSE, "up", "-d", "--wait"));
    }

    @AfterAll
    static void stopAnalyzer() throws Exception {
        run(Duration.ofMinutes(2), append(COMPOSE, "down", "-v", "--remove-orphans"));
    }

    @Test
    void pinsTheApprovedProfileAndKeepsPresidioInsideTheTrustBoundary() throws Exception {
        String containerId = required(Duration.ofSeconds(10),
                append(COMPOSE, "ps", "-q", "analyzer")).output().trim();
        JsonNode container = JSON.readTree(required(Duration.ofSeconds(10),
                List.of("docker", "inspect", containerId)).output()).get(0);
        assertThat(container.path("Config").path("Image").asText()).isEqualTo(IMAGE);
        assertThat(container.path("Config").path("User").asText()).isEqualTo("1001:1001");
        JsonNode host = container.path("HostConfig");
        assertThat(host.path("ReadonlyRootfs").asBoolean()).isTrue();
        assertThat(strings(host.path("CapDrop"))).containsExactly("ALL");
        assertThat(strings(host.path("SecurityOpt"))).contains("no-new-privileges:true");

        // The product topology, not the gate topology, carries the Egress claim.
        Map<String, Object> compose = new Yaml().load(
                Files.readString(ROOT.resolve("docker-compose.yml")));
        Map<String, Object> presidio = nested(nested(compose, "services"), "presidio");
        assertThat(presidio.get("image")).isEqualTo(IMAGE);
        assertThat(presidio).as("Presidio must publish no port").doesNotContainKey("ports");
        assertThat(presidio.get("networks")).isEqualTo(List.of("control"));
        assertThat(presidio.get("read_only")).isEqualTo(true);
        assertThat(presidio.get("cap_drop")).isEqualTo(List.of("ALL"));
        assertThat(nested(nested(compose, "networks"), "control").get("internal"))
                .as("the Gate-to-detector network must be internal").isEqualTo(true);

        PresidioProfile profile = profile();
        assertThat(profile.enabledEntities()).containsExactlyInAnyOrder("CREDIT_CARD",
                "CRYPTO", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS", "MAC_ADDRESS",
                "PHONE_NUMBER", "MEDICAL_LICENSE", "URL");
        assertThat(profile.enabled("PERSON")).isFalse();
        assertThat(profile.enabled("LOCATION")).isFalse();
        assertThat(profile.enabled("NRP")).isFalse();
        assertThat(profile.enabled("DATE_TIME")).isFalse();
        assertThat(profile.scoreThreshold()).isEqualTo(0.75);

        // The debiased corpus earned a lower threshold for three entities. An entity
        // that earned none keeps the default, so it behaves exactly as it did before.
        assertThat(profile.threshold("PHONE_NUMBER")).isEqualTo(0.75);
        assertThat(profile.threshold("MAC_ADDRESS")).isEqualTo(0.6);
        assertThat(profile.threshold("URL")).isEqualTo(0.6);
        assertThat(profile.threshold("IP_ADDRESS")).isEqualTo(0.75);
        assertThat(profile.threshold("EMAIL_ADDRESS")).isEqualTo(0.75);
        // The wire request must not filter out a Finding a per-entity threshold admits.
        assertThat(profile.minimumThreshold()).isEqualTo(0.6);
    }

    @Test
    void maskesApprovedPiiSecretAndEdmForBothProvidersAndRescansTheDerivedTurn() {
        for (Provider provider : providers()) {
            MaskContinuationService service = service(detector());
            String scope = "scope-" + provider.name;

            String source = provider.body(PII_EMAIL + " again " + PII_EMAIL + " card " + CARD
                    + " ip " + IP + " phone " + PHONE + " key " + FAKE_SECRET
                    + " customer " + EDM_EMAIL + " owner " + PERSON);
            MaskContinuationResult result = service.apply(scope, provider.adapter,
                    source.getBytes(StandardCharsets.UTF_8));
            assertThat(result).isInstanceOf(MaskContinuationResult.Masked.class);
            MaskContinuationResult.Masked masked = (MaskContinuationResult.Masked) result;
            String derived = new String(masked.derivedBody(), StandardCharsets.UTF_8);

            assertThat(derived).as("%s DERIVED Turn releases no seeded raw value",
                            provider.name)
                    .doesNotContain(PII_EMAIL, CARD, IP, PHONE, FAKE_SECRET, EDM_EMAIL);
            assertThat(derived).containsPattern("<EMAIL_[0-9]+>")
                    .containsPattern("<ACCOUNT_[0-9]+>")
                    .containsPattern("<IP_[0-9]+>")
                    .containsPattern("<PHONE_[0-9]+>")
                    .containsPattern("<SECRET_[0-9]+>");
            // M3 disabled PERSON, so an unapproved entity must never enforce.
            assertThat(derived).as("a disabled entity must not mask").contains(PERSON);

            // The repeated PII email, the repeated PII email again, then the EDM email.
            List<String> emails = matches(derived, "<EMAIL_[0-9]+>");
            assertThat(emails).as("derived=%s", derived).hasSize(3);
            assertThat(emails.get(1)).as("one value reuses one Placeholder")
                    .isEqualTo(emails.get(0));
            assertThat(emails.get(2)).as("a different value takes a different Placeholder")
                    .isNotEqualTo(emails.get(0));

            DetectionRun presidioRun = run(masked.sourceRuns(), "presidio");
            assertThat(presidioRun.status()).isEqualTo(DetectionStatus.COMPLETE);
            assertThat(presidioRun.reason()).isEmpty();
            assertThat(presidioRun.detectorVersion()).isEqualTo("presidio:broad-pii-en:v1");
            assertThat(presidioRun.findings()).isNotEmpty();

            // The final rescan of the complete DERIVED body is clean for every detector.
            assertThat(masked.finalRuns()).allSatisfy(finalRun ->
                    assertThat(finalRun.status()).isEqualTo(DetectionStatus.COMPLETE));
            assertThat(run(masked.finalRuns(), "presidio").findings()).isEmpty();

            // Durable evidence stays content-free.
            String evidence = presidioRun.evidence().toString();
            assertThat(evidence).doesNotContain(PII_EMAIL, CARD, IP, PHONE, FAKE_SECRET,
                    EDM_EMAIL, "start", "end", "score");
        }
    }

    @Test
    void reusesOnePlaceholderAcrossTurnsInOneScopeAndNeverAcrossScopes() {
        MaskContinuationService service = service(detector());
        Provider openai = providers().getFirst();

        String first = placeholder(service, "scope-linked-a", openai, "<EMAIL_[0-9]+>");
        String later = placeholder(service, "scope-linked-a", openai, "<EMAIL_[0-9]+>");
        assertThat(later).as("one Mask Scope keeps equality across Turns").isEqualTo(first);

        // A new Mask Scope must not let the same value be correlated to the old one.
        String other = placeholder(service, "scope-linked-b", openai, "<EMAIL_[0-9]+>");
        assertThat(other).as("Mask Scopes are unlinkable").isNotEqualTo(first);
    }

    private static List<String> matches(String text, String pattern) {
        var matcher = Pattern.compile(pattern).matcher(text);
        List<String> found = new ArrayList<>();
        while (matcher.find()) {
            found.add(matcher.group());
        }
        return List.copyOf(found);
    }

    @Test
    void anIncompletePresidioRunBlocksTheManagedTurnAndReleasesNoDerivedBytes() {
        // Nothing listens here: the bounded client reports a gap instead of guessing.
        PresidioDetector unreachable = new PresidioDetector(
                new PresidioClient(URI.create("http://127.0.0.1:1")), profile());
        MaskContinuationService service = service(unreachable);

        MaskContinuationResult result = service.apply("scope-gap", new OpenAiResponsesAdapter(),
                providers().getFirst().body(PII_EMAIL + " key " + FAKE_SECRET)
                        .getBytes(StandardCharsets.UTF_8));

        assertThat(result).isInstanceOf(MaskContinuationResult.Failed.class);
        MaskContinuationResult.Failed failed = (MaskContinuationResult.Failed) result;
        assertThat(failed.reason())
                .isEqualTo(MaskContinuationResult.Reason.DETECTION_INCOMPLETE);
        DetectionRun presidioRun = run(failed.sourceRuns(), "presidio");
        assertThat(presidioRun.status()).isEqualTo(DetectionStatus.INCOMPLETE);
        assertThat(presidioRun.reason()).isPresent();
        assertThat(presidioRun.findings()).isEmpty();
    }

    private static String placeholder(MaskContinuationService service, String scope,
                                      Provider provider, String pattern) {
        MaskContinuationResult result = service.apply(scope, provider.adapter,
                provider.body("mail " + PII_EMAIL + " key " + FAKE_SECRET)
                        .getBytes(StandardCharsets.UTF_8));
        assertThat(result).isInstanceOf(MaskContinuationResult.Masked.class);
        String derived = new String(((MaskContinuationResult.Masked) result).derivedBody(),
                StandardCharsets.UTF_8);
        var matcher = Pattern.compile(pattern).matcher(derived);
        assertThat(matcher.find()).isTrue();
        return matcher.group();
    }

    private static DetectionRun run(List<DetectionRun> runs, String detectorId) {
        return runs.stream().filter(value -> value.detectorId().equals(detectorId))
                .findFirst().orElseThrow(() ->
                        new AssertionError("missing detector run: " + detectorId));
    }

    private static PresidioProfile profile() {
        return PresidioProfile.load(DETECTOR.resolve("approved-profile.json"));
    }

    private static PresidioDetector detector() {
        return new PresidioDetector(
                new PresidioClient(URI.create("http://127.0.0.1:" + PORT)), profile());
    }

    private static MaskContinuationService service(PresidioDetector presidio) {
        var fingerprint = Fingerprinter.fullFingerprint(SALT, Fingerprinter.normalize(EDM_EMAIL));
        TypedRegistry registry = TypedRegistry.create("customers", SALT, 1,
                new RegistryRecipe("mask-email", 1),
                Map.of("email", new TypedRegistry.Field("email", ReplacementKind.EMAIL,
                        Set.of(fingerprint))));
        EdmMatcher edm = new EdmMatcher(List.of(), List.of(registry), 50_000);
        SecretDetector secrets = new SecretDetector();
        Map<String, Action> ruleActions = Map.of(
                "edm-customers", Action.MASK,
                "aws-access-token", Action.MASK,
                "email-address", Action.MASK,
                "credit-card", Action.MASK,
                "ip-address", Action.MASK,
                "phone-number", Action.MASK);
        PolicyEngine policy = new PolicyEngine(secrets, new Masker(), Action.FLAG,
                ruleActions, edm, 10);
        MaskScopeStore scopes = new MaskScopeStore();
        return new MaskContinuationService(
                new MaskDetectionService(secrets, edm, policy, presidio),
                new MaskPlanner(scopes), scopes);
    }

    private static List<Provider> providers() {
        return List.of(
                new Provider("openai", new OpenAiResponsesAdapter(), input -> """
                        {"model":"gpt-5-codex","instructions":"Use the fake fixture.",\
                        "input":"%s"}""".formatted(input)),
                new Provider("anthropic", new AnthropicMessagesAdapter(), input -> """
                        {"model":"claude-haiku-4-5-20251001","max_tokens":64,\
                        "messages":[{"role":"user","content":"%s"}]}""".formatted(input)));
    }

    private record Provider(String name, ProviderAdapter adapter,
                            java.util.function.UnaryOperator<String> shape) {
        String body(String input) {
            return shape.apply(input);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> nested(Map<String, Object> parent, String key) {
        Object value = parent.get(key);
        assertThat(value).as("missing compose key: %s", key).isInstanceOf(Map.class);
        return (Map<String, Object>) value;
    }

    private static List<String> strings(JsonNode values) {
        List<String> result = new ArrayList<>();
        values.forEach(value -> result.add(value.asText()));
        return result;
    }

    private static List<String> append(List<String> prefix, String... suffix) {
        List<String> command = new ArrayList<>(prefix);
        command.addAll(List.of(suffix));
        return command;
    }

    private static CommandResult required(Duration timeout, List<String> command)
            throws Exception {
        CommandResult result = run(timeout, command);
        assertThat(result.exitCode()).as("command output:%n%s", result.output()).isZero();
        return result;
    }

    private static CommandResult run(Duration timeout, List<String> command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        CompletableFuture<byte[]> output = CompletableFuture.supplyAsync(() -> {
            try {
                return process.getInputStream().readAllBytes();
            } catch (IOException exception) {
                throw new UncheckedIOException("failed to read command output", exception);
            }
        });
        if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("command timed out: " + String.join(" ", command));
        }
        return new CommandResult(process.exitValue(),
                new String(output.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8));
    }

    private record CommandResult(int exitCode, String output) { }
}
