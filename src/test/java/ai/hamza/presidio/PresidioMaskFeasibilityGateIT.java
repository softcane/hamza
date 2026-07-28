package ai.hamza.presidio;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PresidioMaskFeasibilityGateIT {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String IMAGE = "ghcr.io/data-privacy-stack/presidio-analyzer@sha256:"
            + "286e3fa7f3a7426e775e8564fe1870f1ba8f999d3ab8bbb8cc46a44355d9d6e9";
    private static final Set<String> ENTITIES = Set.of(
            "CREDIT_CARD", "CRYPTO", "DATE_TIME", "EMAIL_ADDRESS", "IBAN_CODE",
            "IP_ADDRESS", "MAC_ADDRESS", "NRP", "LOCATION", "PERSON", "PHONE_NUMBER",
            "MEDICAL_LICENSE", "URL");
    /** The entities that enforce today. Lowering a threshold may never shrink this set. */
    private static final Set<String> ENABLED = Set.of(
            "CREDIT_CARD", "CRYPTO", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS",
            "MAC_ADDRESS", "PHONE_NUMBER", "MEDICAL_LICENSE", "URL");
    private static final Set<String> REJECTED =
            Set.of("DATE_TIME", "NRP", "LOCATION", "PERSON");
    /** The only failures that may move an entity out of {@link #ENABLED}. */
    private static final Set<String> SAFETY_FAILURES =
            Set.of("precision_below_floor", "benign_false_findings_above_floor");

    @Test
    void evaluatesPinnedIsolatedAnalyzerAndEnablesOnlyPassingEntities() throws Exception {
        Path root = Path.of("").toAbsolutePath().normalize();
        Path detector = root.resolve("detector/presidio");
        String project = "hamza-presidio-gate-" + ProcessHandle.current().pid();
        List<String> compose = List.of("docker", "compose", "-p", project, "-f",
                detector.resolve("compose.yaml").toString());

        try {
            required(Duration.ofMinutes(3), append(compose, "up", "-d", "--wait"));
            String containerId = required(Duration.ofSeconds(10),
                    append(compose, "ps", "-q", "analyzer")).output().trim();
            assertThat(containerId).isNotBlank();
            assertIsolation(containerId);

            CommandResult egress = run(Duration.ofSeconds(10), List.of(
                    "docker", "exec", containerId, "curl", "--silent", "--show-error",
                    "--max-time", "2", "https://example.com"));
            assertThat(egress.exitCode()).as("internal network must deny external Egress")
                    .isNotZero();

            CommandResult evaluation = required(Duration.ofMinutes(10), List.of(
                    "docker", "exec", containerId, "python",
                    "/evaluation/presidio_feasibility.py"));
            JsonNode actual = JSON.readTree(evaluation.output());
            validateEvaluation(detector, actual);
            Path generated = root.resolve("target/presidio-evaluation-report.json");
            Files.createDirectories(generated.getParent());
            JSON.writerWithDefaultPrettyPrinter().writeValue(generated.toFile(), actual);

            String logs = required(Duration.ofSeconds(10),
                    List.of("docker", "logs", containerId)).output();
            assertThat(logs).doesNotContain("POST /analyze", "case t-", "case h-",
                    "example.com", "fixture-");
        } finally {
            run(Duration.ofMinutes(2), append(compose, "down", "-v", "--remove-orphans"));
        }
    }

    private static void assertIsolation(String containerId) throws Exception {
        JsonNode container = JSON.readTree(required(Duration.ofSeconds(10),
                List.of("docker", "inspect", containerId)).output()).get(0);
        assertThat(container.path("Config").path("Image").asText()).isEqualTo(IMAGE);
        assertThat(container.path("Config").path("User").asText()).isEqualTo("1001:1001");
        JsonNode host = container.path("HostConfig");
        assertThat(host.path("ReadonlyRootfs").asBoolean()).isTrue();
        assertThat(strings(host.path("CapDrop"))).containsExactly("ALL");
        assertThat(strings(host.path("SecurityOpt"))).contains("no-new-privileges:true");
        assertThat(host.path("PortBindings").isEmpty()).isTrue();
        assertThat(host.path("DeviceRequests").isMissingNode()
                || host.path("DeviceRequests").isNull()
                || host.path("DeviceRequests").isEmpty()).isTrue();
        assertThat(host.path("Tmpfs").has("/tmp")).isTrue();

        JsonNode mounts = container.path("Mounts");
        assertThat(mounts).allSatisfy(mount -> assertThat(mount.path("RW").asBoolean()).isFalse());
        assertThat(mounts).anySatisfy(mount ->
                assertThat(mount.path("Destination").asText()).isEqualTo("/evaluation"));

        JsonNode networks = container.path("NetworkSettings").path("Networks");
        assertThat(networks.size()).isOne();
        String networkId = networks.elements().next().path("NetworkID").asText();
        JsonNode network = JSON.readTree(required(Duration.ofSeconds(10),
                List.of("docker", "network", "inspect", networkId)).output()).get(0);
        assertThat(network.path("Internal").asBoolean()).isTrue();

        JsonNode image = JSON.readTree(required(Duration.ofSeconds(10),
                List.of("docker", "image", "inspect", IMAGE)).output()).get(0);
        assertThat(container.path("Image").asText()).isEqualTo(image.path("Id").asText());
    }

    private static void validateEvaluation(Path detector, JsonNode actual) throws Exception {
        JsonNode candidate = JSON.readTree(detector.resolve("candidate-profile.json").toFile());
        JsonNode approved = JSON.readTree(detector.resolve("approved-profile.json").toFile());
        JsonNode recorded = JSON.readTree(detector.resolve("evaluation-report.json").toFile());

        assertThat(strings(candidate.path("entities"))).containsExactlyInAnyOrderElementsOf(ENTITIES);
        assertThat(strings(actual.path("evaluated_entities")))
                .containsExactlyInAnyOrderElementsOf(ENTITIES);
        assertThat(actual.path("image").asText()).isEqualTo(IMAGE);
        assertThat(actual.path("all_calls_complete").asBoolean()).isTrue();
        assertThat(actual.path("content_free").asBoolean()).isTrue();
        assertThat(actual.path("corpus_counts").path("partitions_disjoint").asBoolean()).isTrue();
        assertThat(actual.path("corpus_counts").path("tuning_positive_occurrences_per_entity")
                .asInt()).isEqualTo(100);
        assertThat(actual.path("corpus_counts").path("holdout_positive_occurrences_per_entity")
                .asInt()).isEqualTo(100);
        assertThat(actual.path("corpus_counts").path("tuning_benign_turns").asInt())
                .isEqualTo(3000);
        assertThat(actual.path("corpus_counts").path("holdout_benign_turns").asInt())
                .isEqualTo(10000);

        Set<String> enabled = Set.copyOf(strings(actual.path("approved_entities")));
        assertThat(enabled).isEqualTo(Set.copyOf(strings(approved.path("enabled_entities"))));
        Set<String> rejected = Set.copyOf(entityNames(actual.path("rejected_entities")));
        assertThat(rejected).isEqualTo(Set.copyOf(entityNames(approved.path("disabled_entities"))));
        assertThat(enabled).doesNotContainAnyElementsOf(rejected);
        assertThat(enabled).as("every entity that enforces today must keep enforcing")
                .isEqualTo(ENABLED);
        assertThat(rejected).isEqualTo(REJECTED);

        // An entity leaves the enabled set only when it masks text that is not PII.
        // Missing PII is the defect the debiased corpus exposes, never a reason to
        // stop enforcing.
        actual.path("rejected_entities").forEach(entry -> {
            List<String> reasons = strings(entry.path("reasons"));
            assertThat(reasons).isNotEmpty();
            assertThat(reasons).as("%s was disabled without a safety failure",
                    entry.path("entity").asText()).containsAnyElementsOf(SAFETY_FAILURES);
        });

        // Each approved entity carries its own threshold; an entity with no recorded
        // override enforces at the profile default.
        double defaultThreshold = actual.path("selected_threshold").asDouble();
        JsonNode thresholds = actual.path("entity_thresholds");
        JsonNode overrides = approved.path("entity_thresholds");
        for (String entity : enabled) {
            double threshold = thresholds.path(entity).asDouble(-1.0);
            assertThat(threshold).as("recorded threshold for %s", entity)
                    .isBetween(0.0, 1.0);
            double enforced = overrides.has(entity)
                    ? overrides.path(entity).asDouble(-1.0)
                    : approved.path("selected_threshold").asDouble(-1.0);
            assertThat(enforced).as("the approved profile must enforce what %s was "
                    + "evaluated at", entity).isEqualTo(threshold);
        }

        // An approved entity that misses a floor keeps the default and is listed as a
        // gap, so no entity may quietly enforce below a threshold it never earned.
        Set<String> gaps = Set.copyOf(entityNames(actual.path("quality_gaps")));
        assertThat(enabled).containsAll(gaps);
        actual.path("quality_gaps").forEach(entry -> {
            String entity = entry.path("entity").asText();
            assertThat(thresholds.path(entity).asDouble()).as(
                    "%s missed a floor, so it may not enforce below the default", entity)
                    .isEqualTo(defaultThreshold);
            assertThat(strings(entry.path("reasons")))
                    .doesNotContain("benign_false_findings_above_floor");
        });

        JsonNode floors = candidate.path("quality_floors");
        for (String entity : ENTITIES) {
            JsonNode metrics = actual.path("holdout_metrics").path(entity);
            assertThat(metrics.path("positive_turns").asInt()).isEqualTo(100);
            assertThat(metrics.path("benign_turns").asInt()).isEqualTo(10000);
            assertThat(metrics.path("complete").asBoolean()).isTrue();
            if (!enabled.contains(entity)) {
                continue;
            }
            // Every approved entity meets both safety floors at its own threshold.
            // Precision is only a measurement where the entity produced a Finding;
            // at zero Findings it is an undefined 0/0, not evidence of over-masking.
            assertThat(metrics.path("benign_false_findings_per_10000_turns").asDouble())
                    .isLessThanOrEqualTo(
                            floors.path("benign_false_findings_per_10000_turns").asDouble());
            assertThat(metrics.path("p95_ms").asDouble())
                    .isLessThanOrEqualTo(floors.path("p95_ms").asDouble());
            if (metrics.path("findings").asInt() > 0) {
                assertThat(metrics.path("precision").asDouble())
                        .isGreaterThanOrEqualTo(floors.path("precision").asDouble());
            }
            if (gaps.contains(entity)) {
                continue;
            }
            // An entity with no recorded gap met every floor at its threshold.
            assertThat(metrics.path("precision").asDouble())
                    .isGreaterThanOrEqualTo(floors.path("precision").asDouble());
            assertThat(metrics.path("recall").asDouble())
                    .isGreaterThanOrEqualTo(floors.path("recall").asDouble());
            assertThat(metrics.path("f2").asDouble())
                    .isGreaterThanOrEqualTo(floors.path("f2").asDouble());
            assertThat(metrics.path("exact_span_reliability").asDouble())
                    .isGreaterThanOrEqualTo(
                            floors.path("exact_span_reliability").asDouble());
        }

        assertThat(strings(recorded.path("approved_entities"))).containsExactlyElementsOf(
                strings(actual.path("approved_entities")));
        assertThat(entityNames(recorded.path("rejected_entities")))
                .containsExactlyElementsOf(entityNames(actual.path("rejected_entities")));
        assertThat(entityNames(recorded.path("quality_gaps")))
                .containsExactlyElementsOf(entityNames(actual.path("quality_gaps")));
        assertThat(recorded.path("selected_threshold").asDouble())
                .isEqualTo(defaultThreshold);
        assertThat(recorded.path("entity_thresholds")).isEqualTo(thresholds);
        for (String entity : ENTITIES) {
            JsonNode expected = recorded.path("holdout_metrics").path(entity);
            JsonNode observed = actual.path("holdout_metrics").path(entity);
            for (String field : List.of("findings", "precision", "recall", "f2",
                    "exact_span_reliability", "benign_false_findings",
                    "benign_false_findings_per_10000_turns", "positive_turns",
                    "benign_turns", "complete")) {
                assertThat(observed.path(field)).isEqualTo(expected.path(field));
            }
        }

        String serialized = JSON.writeValueAsString(actual);
        assertThat(serialized).doesNotContain("case t-", "case h-", "example.com",
                "fixture-", "\"text\"", "\"start\"", "\"end\"");
    }

    private static List<String> strings(JsonNode values) {
        List<String> result = new ArrayList<>();
        values.forEach(value -> result.add(value.asText()));
        return result;
    }

    private static List<String> entityNames(JsonNode values) {
        List<String> result = new ArrayList<>();
        values.forEach(value -> result.add(value.path("entity").asText()));
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
                throw new IllegalStateException("failed to read command output", exception);
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
