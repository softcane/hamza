package ai.hamza.attest;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class FlowFeedReconcilerTest {

    @Test
    void parsesHubbleSubsetAndCountsProviderDomainFlowsOnly() {
        String raw = String.join("\n",
                "{\"timestamp\":\"2026-07-06T10:00:01Z\",\"destination_fqdn\":\"api.openai.com\","
                        + "\"verdict\":\"FORWARDED\",\"bytes\":50}",
                "{\"timestamp\":\"2026-07-06T10:00:02Z\",\"destination_fqdn\":\"example.test\","
                        + "\"verdict\":\"FORWARDED\",\"bytes\":10}",
                "{\"timestamp\":\"2026-07-06T10:00:03Z\",\"destination_fqdn\":\"api.openai.com\","
                        + "\"verdict\":\"DROPPED\",\"bytes\":10}",
                "{\"timestamp\":\"2026-07-06T10:00:04Z\",\"destination_ip\":\"203.0.113.10\","
                        + "\"verdict\":\"FORWARDED\",\"bytes\":10}");

        var entries = FlowFeedReconciler.parse(raw);
        var summary = FlowFeedReconciler.summarize(entries, Set.of("api.openai.com"),
                Instant.parse("2026-07-06T10:00:00Z"),
                Instant.parse("2026-07-06T11:00:00Z"));

        assertThat(summary.providerEvents()).isEqualTo(1);
        assertThat(summary.providerBytes()).isEqualTo(50);
        assertThat(summary.providerFlowsByDestination()).containsEntry("api.openai.com", 1L);
        assertThat(summary.unclassifiedEvents()).isEqualTo(1);
    }
}
