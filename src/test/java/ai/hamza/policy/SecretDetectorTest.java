package ai.hamza.policy;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** Detector true/false positives across the v1 rule set. */
class SecretDetectorTest {

    private static final String AWS_ACCESS_TOKEN = "AKIAABCDEFGHIJKLMNOP";
    private static final String GITHUB_PAT = "ghp_9xs703a3j1eqgf9uzht09b3opv765kzeio23";
    private static final String GCP_API_KEY = "AIzajpLRMJElxpOQKT3-Qc0BndHY-0ayZdTY1OZ";
    private static final String SLACK_BOT_TOKEN = "xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD";
    private static final String ANTHROPIC_API_KEY =
            "sk-ant-api03-rc13y9hsyia_z6-unsstwkq4qmqi5fsz8ebbt-wbk77mp5oiuol72rdu_3nrh_grp2mw4w7c32v2_0201zvq9cmr4-qflAA";
    private static final String NPM_ACCESS_TOKEN = "npm_ws3c38adbd8967mtw1n9ei5pcqa6ab9qvh8c";

    private final SecretDetector detector = new SecretDetector();

    private Set<String> rules(String text) {
        return detector.detect(text).stream().map(SecretDetector.Match::rule).collect(java.util.stream.Collectors.toSet());
    }

    @Test
    void detectsAwsAccessToken() {
        assertThat(rules("here is " + AWS_ACCESS_TOKEN + " in the prompt")).contains("aws-access-token");
    }

    @Test
    void detectsGitHubAndGoogleAndSlackTokens() {
        assertThat(rules("token " + GITHUB_PAT)).contains("github-pat");
        assertThat(rules("key " + GCP_API_KEY)).contains("gcp-api-key");
        assertThat(rules("slack " + SLACK_BOT_TOKEN)).contains("slack-bot-token");
    }

    @Test
    void detectsPrivateKeyAndJwt() {
        // Upstream private-key rule (Phase 3, replacing the legacy private-key-block) needs a
        // real >=64-char body and a closing delimiter; a bare header no longer matches.
        String privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"
                + "MIIEowIBAAKCAQEA7Xk9Qm2Rf4Tz8Yb3Nc6Vd1Wg5Hj0Kp9Lq2Ms8Ru4Sv7Tw3Ux6Zy0Ab\n"
                + "Bc4De1Fg8Hi5Jk2Lm9No6Pq3Rs0Tu7Vw4Xy1Za8Bc5Df2Gh9Ij6Kl3Mn0Op7Qr4St1Uv8Wx\n"
                + "-----END RSA PRIVATE KEY-----";
        assertThat(rules(privateKey)).contains("private-key");
        String jwt = "eyJhbGciOiJIUzI1NiI.eyJzdWIiOiIxMjM0NTY3ODkw.SflKxwRJSMeKKF2QT4fwpM";
        assertThat(rules(jwt)).contains("jwt");
    }

    @Test
    void detectsSecretsInsideJsonEscapedQuotes() {
        // A real Claude Code turn JSON-encodes the developer's message, so a quoted
        // assignment like  aws_secret_access_key = "3wU5.../RY"  reaches the Gate as
        //   ... = \"3wU5.../RY\"
        // The file-format quote class excludes the backslash, so the raw-wire scan misses
        // it. Un-escaping the JSON string before matching must recover it.
        String awsSecret = "3wU5BcAhbRkF4MUXBYMrHoYGaNLuPNCPiGVbUDDj";
        String wireBody = "{\"messages\":[{\"role\":\"user\",\"content\":"
                + "\"config line: aws_secret_access_key = \\\"" + awsSecret + "\\\"\"}]}";
        assertThat(rules(wireBody))
                .as("AWS secret key inside JSON-escaped quotes must be detected")
                .contains("aws-secret-access-key");
    }

    @Test
    void detectsGithubTokenInsideJsonEscapedQuotes() {
        String wireBody = "{\"content\":\"token = \\\"" + GITHUB_PAT + "\\\"\"}";
        assertThat(rules(wireBody))
                .as("identifier-shaped key inside JSON-escaped quotes stays detected")
                .contains("github-pat");
    }

    @Test
    void detectsHighEntropyAssignmentButNotLowEntropyWords() {
        // High-entropy value after a sensitive key name -> flagged.
        assertThat(rules("api_key = 9fA3kZ72Qp1XbR8sWuTyLmNc0DeHgVi4"))
                .contains("high-entropy-assignment");
        // A sensitive key with a low-entropy, wordy value -> not flagged.
        assertThat(rules("password = correcthorsebatterystaple"))
                .doesNotContain("high-entropy-assignment");
    }

    @Test
    void detectsImportedHighConfidenceRules() {
        assertThat(rules("charge sk_live_4eC39HqLyjWDarjtT1zdp7dc now")).contains("stripe-access-token");
        assertThat(rules("key " + ANTHROPIC_API_KEY)).contains("anthropic-api-key");
        assertThat(rules(NPM_ACCESS_TOKEN)).contains("npm-access-token");
        assertThat(rules("glpat-ABCDEFGHIJKLMNOP1234")).contains("gitlab-pat");
        assertThat(rules("post to https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"))
                .contains("slack-webhook-url");
    }

    @Test
    void importedRulesDoNotFireOnNearMisses() {
        // Too short / wrong shape must not match the distinctive-prefix imported rules.
        assertThat(rules("sk_live_short")).doesNotContain("stripe-access-token");
        assertThat(rules("sk-antelope-migration-plan")).doesNotContain("anthropic-api-key");
        assertThat(rules("run npm_install to fetch deps")).doesNotContain("npm-access-token");
        assertThat(rules("see https://hooks.slack.com/services/overview for docs"))
                .doesNotContain("slack-webhook-url");
    }

    @Test
    void cleanProseHasNoFindings() {
        assertThat(detector.detect("Please refactor the function to handle null inputs and add a unit test."))
                .isEmpty();
    }

    @Test
    void reportsAccurateSpans() {
        String text = "x " + AWS_ACCESS_TOKEN + " y";
        List<SecretDetector.Match> matches = detector.detect(text);
        assertThat(matches).hasSize(1);
        SecretDetector.Match m = matches.getFirst();
        assertThat(text.substring(m.start(), m.end())).isEqualTo(AWS_ACCESS_TOKEN);
    }

    @Test
    void largeInputsAreScannedInOverlappingWindowsWithoutLosingSpans() {
        String text = "x".repeat(65_530) + " " + AWS_ACCESS_TOKEN + " y";

        List<SecretDetector.Match> matches = detector.detect(text);

        assertThat(matches).hasSize(1);
        SecretDetector.Match m = matches.getFirst();
        assertThat(text.substring(m.start(), m.end())).isEqualTo(AWS_ACCESS_TOKEN);
    }

    @Test
    void lowSignalLargeFillerProducesNoFindings() {
        assertThat(detector.detect("x".repeat(100_000))).isEmpty();
    }
}
