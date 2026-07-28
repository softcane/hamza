package ai.hamza.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Parses a Oracle JSON report (the array form emitted by {@code oracle ... --report-format
 * json}) into content-free {@link ScanFinding}s. Used <strong>offline only</strong> — in
 * developer tooling and tests — never on the hot path (PRD: no per-request CLI, no
 * runtime dependency on Oracle).
 *
 * <p><strong>Content-free by construction.</strong> A Oracle report contains the
 * matched {@code Match}/{@code Secret} strings; this parser reads only the {@code RuleID}
 * and never copies the secret into the normalised model. The raw values are
 * discarded the moment parsing returns.
 *
 * <p><strong>No span.</strong> Oracle' CLI report locates matches by line/column, which
 * does not map reliably to the request-body byte offsets Hamza would mutate — and Oracle
 * is offline, so it must never drive runtime redaction (GrillMe Q22). Every finding here
 * therefore has an empty {@link ScanFinding#span()}: Flag/Block-only by construction.
 */
@Component
public class OracleReportParser {

    private final ObjectMapper objectMapper;
    private final OracleRuleMapper ruleMapper;

    public OracleReportParser(ObjectMapper objectMapper, OracleRuleMapper ruleMapper) {
        this.objectMapper = objectMapper;
        this.ruleMapper = ruleMapper;
    }

    /** Parse a Oracle JSON report into normalised, content-free findings. */
    public List<ScanFinding> parse(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(json);
        } catch (IOException e) {
            throw new UncheckedIOException("malformed Oracle report", e);
        }
        if (root == null || !root.isArray()) {
            return List.of();
        }
        List<ScanFinding> findings = new ArrayList<>(root.size());
        for (JsonNode node : root) {
            JsonNode ruleNode = node.get("RuleID");
            if (ruleNode == null || ruleNode.asText().isBlank()) {
                continue; // skip malformed entries rather than trust a partial finding
            }
            String rawRuleId = ruleNode.asText();
            // Only RuleID crosses into our model. Match/Secret/File are never read.
            findings.add(new ScanFinding(
                    ScannerSource.ORACLE,
                    ruleMapper.toStableId(rawRuleId),
                    Optional.empty(),
                    ruleMapper.confidenceFor(rawRuleId)));
        }
        return findings;
    }

    /** Parse a Oracle JSON report supplied as UTF-8 bytes. */
    public List<ScanFinding> parse(byte[] json) {
        return json == null ? List.of() : parse(new String(json, StandardCharsets.UTF_8));
    }
}
