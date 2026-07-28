package ai.hamza.policy;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RulepackExecutorTest {

    @Test
    void stopwordsApplyToCapturedSecretNotFullMatch() {
        SecretDetector detector = detectorWith(List.of(
                new RulepackAllowlist("match", List.of(), List.of("sample"))));

        assertThat(detector.detect("sample_token = ABCDEFGH12345678"))
                .as("old whole-match stopword behavior would suppress this because the key name contains sample")
                .extracting(SecretDetector.Match::rule)
                .containsExactly("test-rule");
    }

    @Test
    void allowRegexCanTargetTheEnclosingLine() {
        SecretDetector detector = detectorWith(List.of(
                new RulepackAllowlist("line", List.of("ALLOW_THIS_LINE"), List.of())));

        assertThat(detector.detect("ALLOW_THIS_LINE token = ABCDEFGH12345678")).isEmpty();
        assertThat(detector.detect("token = ABCDEFGH12345678"))
                .extracting(SecretDetector.Match::rule)
                .containsExactly("test-rule");
    }

    @Test
    void allowRegexCanTargetTheFullMatch() {
        SecretDetector detector = detectorWith(List.of(
                new RulepackAllowlist("match", List.of("token\\s*="), List.of())));

        assertThat(detector.detect("token = ABCDEFGH12345678")).isEmpty();
    }

    @Test
    void allowRegexCanTargetTheCapturedSecret() {
        SecretDetector detector = detectorWith(List.of(
                new RulepackAllowlist("secret", List.of("SAFESECRET\\d+"), List.of())));

        assertThat(detector.detect("token = SAFESECRET123456")).isEmpty();
        assertThat(detector.detect("token = RISKSECRET123456"))
                .extracting(SecretDetector.Match::rule)
                .containsExactly("test-rule");
    }

    @Test
    void defaultSecretIsFirstCaptureGroupNotFullMatch() {
        // Upstream semantics: no secretGroup + capture groups present -> the first
        // non-empty group is the secret. The stopword "acces" sits in the variable
        // name, so full-match semantics would suppress this AWS-style finding.
        SecretDetector detector = new SecretDetector(new RulepackExecutor(List.of(
                new RulepackExecutor.RuleSpec(
                        "aws-style-rule",
                        "(?i)[\\w.-]{0,50}?(?:access|secret|key)[\\w.-]{0,20}=([A-Za-z0-9/+=]{40})",
                        0,
                        3.0,
                        List.of("key"),
                        List.of(new RulepackAllowlist(null, List.of(), List.of("acces", "aws_")))))));

        assertThat(detector.detect("export AWS_SECRET_ACCESS_KEY=3wU5BcAhbRkF4MUXBYMrHoYGaNLuPNCPiGVbUDDj"))
                .extracting(SecretDetector.Match::rule)
                .containsExactly("aws-style-rule");
    }

    @Test
    void defaultSecretStaysFullMatchWhenRegexHasNoCaptureGroup() {
        SecretDetector detector = new SecretDetector(new RulepackExecutor(List.of(
                new RulepackExecutor.RuleSpec(
                        "groupless-rule",
                        "(?i)token=[A-Z0-9]{16}",
                        0,
                        0.0,
                        List.of("token"),
                        List.of(new RulepackAllowlist(null, List.of(), List.of("token=")))))));

        assertThat(detector.detect("token=ABCDEFGH12345678"))
                .as("stopword targets the full match when nothing is captured, matching upstream")
                .isEmpty();
    }

    private static SecretDetector detectorWith(List<RulepackAllowlist> allowlists) {
        return new SecretDetector(new RulepackExecutor(List.of(new RulepackExecutor.RuleSpec(
                "test-rule",
                "(?i)\\b(?:sample_token|token)\\b\\s*=\\s*([A-Za-z0-9]{8,})",
                1,
                0.0,
                List.of("token"),
                allowlists))));
    }
}
