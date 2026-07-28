package ai.hamza.attest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Parses the v1 network-flow ledger feed for attestation reconciliation.
 * The accepted JSONL subset is intentionally content-free: timestamp, destination
 * FQDN/IP, verdict, and bytes only. Provider classification uses the Adapter registry's
 * domain list; IP-only rows are counted as unclassified rather than guessed.
 */
public final class FlowFeedReconciler {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private FlowFeedReconciler() {
    }

    public record FlowEntry(String timestamp, String destinationFqdn, String destinationIp,
                            String verdict, long bytes) {
    }

    public record Summary(long providerEvents, long providerBytes,
                          Map<String, Long> providerFlowsByDestination,
                          long unclassifiedEvents) {
    }

    public static List<FlowEntry> parse(String rawJsonl) {
        List<FlowEntry> out = new ArrayList<>();
        if (rawJsonl == null || rawJsonl.isBlank()) {
            return out;
        }
        for (String line : rawJsonl.split("\n")) {
            FlowEntry entry = parseLine(line);
            if (entry != null) {
                out.add(entry);
            }
        }
        return out;
    }

    public static FlowEntry parseLine(String line) {
        String trimmed = line == null ? "" : line.strip();
        if (trimmed.isEmpty() || trimmed.charAt(0) != '{') {
            return null;
        }
        try {
            JsonNode n = MAPPER.readTree(trimmed);
            return new FlowEntry(
                    firstText(n, "timestamp", "time"),
                    firstText(n, "destination_fqdn", "destinationFqdn", "destinationFQDN", "fqdn"),
                    firstText(n, "destination_ip", "destinationIp", "destinationIP", "ip"),
                    firstText(n, "verdict"),
                    n.path("bytes").asLong(0));
        } catch (Exception e) {
            return null;
        }
    }

    public static Summary summarize(List<FlowEntry> entries, Set<String> providerDomains,
                                    Instant fromInclusive, Instant toExclusive) {
        Set<String> domains = providerDomains == null ? Set.of() : providerDomains;
        long providerEvents = 0;
        long providerBytes = 0;
        long unclassified = 0;
        Map<String, Long> byDestination = new TreeMap<>();
        for (FlowEntry e : entries == null ? List.<FlowEntry>of() : entries) {
            Instant ts = parseOrNull(e.timestamp());
            if (ts == null || ts.isBefore(fromInclusive) || !ts.isBefore(toExclusive)) {
                continue;
            }
            if (isDenied(e.verdict())) {
                continue;
            }
            if (e.destinationFqdn() == null || e.destinationFqdn().isBlank()) {
                if (e.destinationIp() != null && !e.destinationIp().isBlank()) {
                    unclassified++;
                }
                continue;
            }
            String fqdn = e.destinationFqdn().toLowerCase();
            if (!domains.contains(fqdn)) {
                continue;
            }
            providerEvents++;
            providerBytes += Math.max(0, e.bytes());
            byDestination.merge(fqdn, 1L, Long::sum);
        }
        return new Summary(providerEvents, providerBytes, byDestination, unclassified);
    }

    private static boolean isDenied(String verdict) {
        if (verdict == null || verdict.isBlank()) {
            return false;
        }
        String v = verdict.toUpperCase();
        return v.contains("DROP") || v.contains("DENY") || v.contains("DENIED");
    }

    private static String firstText(JsonNode node, String... names) {
        for (String name : names) {
            JsonNode value = node.path(name);
            if (value.isTextual() && !value.asText().isBlank()) {
                return value.asText();
            }
        }
        return "";
    }

    private static Instant parseOrNull(String iso) {
        try {
            return Instant.parse(iso);
        } catch (Exception e) {
            return null;
        }
    }
}
