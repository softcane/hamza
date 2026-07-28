package ai.hamza.attest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Reconciles the independent Envoy access-log ledger against the Gate Record ledger
 * Envoy sees every byte it forwards to a Provider; the Gate Record only
 * exists if ext_proc actually recorded the Turn. A provider-bound request Envoy logged
 * with <em>no</em> matching Record is a coverage gap — e.g. a fail-open window where
 * hamza-core was down — and the report must list it as such, never imply full coverage.
 *
 * <p>The access log is content-free by construction (envoy.yaml logs method, path,
 * status, response detail, cluster, request-id, and byte counts only — never headers or
 * bodies). M10b reconciles Envoy to Records by request id so blocked Records can no
 * longer net out real fail-open Egress.
 */
public final class AccessLogReconciler {

    /** The name of the Envoy cluster that forwards to a Provider (see envoy.yaml). */
    public static final String PROVIDER_CLUSTER = "provider_upstream";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AccessLogReconciler() {
    }

    /** One Envoy access-log line, content-free. */
    public record AccessEntry(String startTime, String method, String path,
                              int responseCode, String upstreamCluster, String requestId,
                              long bytesReceived, long bytesSent, String responseCodeDetails) {
    }

    /**
     * The reconciliation outcome for one window. {@code providerRequests} is what Envoy
     * forwarded to a Provider; {@code recordsMatched} is how many were also recorded;
     * {@code coverageGaps} is the shortfall (provider requests with no Record).
     * {@code recordsWithoutEnvoyEvidence} is the inverse anomaly (more Records than
     * Envoy saw — surfaced as a discrepancy, not silently dropped).
     */
    public record Reconciliation(long providerRequests, long records, long recordsMatched,
                                 long coverageGaps, long recordsWithoutEnvoyEvidence,
                                 Map<String, Long> providerRequestsByPath,
                                 long flowProviderEvents, long flowBytes,
                                 long flowWithoutEnvoyEvidence, long envoyWithoutFlowEvidence,
                                 long failOpenUninspectedMinutes,
                                 Map<String, Long> failOpenRequestsByMinute,
                                 long inspectedEgressBytes, long providerEgressBytes,
                                 long uninspectedEgressBytes, long recordsMissingByteCounts,
                                 Map<String, Long> providerFlowsByDestination,
                                 long unclassifiedFlowEvents,
                                 String note) {

        public boolean hasLedgerMismatch() {
            return coverageGaps > 0
                    || recordsWithoutEnvoyEvidence > 0
                    || flowWithoutEnvoyEvidence > 0
                    || envoyWithoutFlowEvidence > 0
                    || unclassifiedFlowEvents > 0;
        }

        /** Provider traffic lacking at least one required control-plane explanation. */
        public long unexplainedProviderRequests() {
            try {
                return Math.addExact(Math.addExact(coverageGaps,
                        flowWithoutEnvoyEvidence), unclassifiedFlowEvents);
            } catch (ArithmeticException overflow) {
                return Long.MAX_VALUE;
            }
        }
    }

    /** Parse one JSON access-log line, or {@code null} if it isn't a Hamza access line. */
    public static AccessEntry parseLine(String line) {
        String trimmed = line.strip();
        if (trimmed.isEmpty() || trimmed.charAt(0) != '{') {
            return null;
        }
        try {
            JsonNode n = MAPPER.readTree(trimmed);
            if (!"access".equals(n.path("log").asText(""))) {
                return null;
            }
            // Strip any query string: the report aggregates by path, and query params
            // are the one place a URL could carry content (content-free by construction).
            String path = n.path("path").asText("");
            int q = path.indexOf('?');
            if (q >= 0) {
                path = path.substring(0, q);
            }
            return new AccessEntry(
                    n.path("start_time").asText(""),
                    n.path("method").asText(""),
                    path,
                    n.path("response_code").asInt(0),
                    n.path("upstream_cluster").asText(""),
                    n.path("request_id").asText(""),
                    n.path("bytes_received").asLong(0),
                    n.path("bytes_sent").asLong(0),
                    n.has("response_code_details") ? n.path("response_code_details").asText("") : null);
        } catch (Exception e) {
            return null;
        }
    }

    /** Parse every access line from a raw log dump, skipping non-access (operational) lines. */
    public static List<AccessEntry> parse(String rawLog) {
        List<AccessEntry> out = new ArrayList<>();
        for (String line : rawLog.split("\n")) {
            AccessEntry e = parseLine(line);
            if (e != null) {
                out.add(e);
            }
        }
        return out;
    }

    /**
     * Reconcile provider-bound access entries in {@code [from, to)} against the count of
     * Gate Records in the same window.
     */
    public static Reconciliation reconcile(List<AccessEntry> entries, long recordCount,
                                           String fromInclusive, String toExclusive) {
        Instant from = parseOrMin(fromInclusive);
        Instant to = parseOrMax(toExclusive);
        long providerRequests = 0;
        Map<String, Long> byPath = new TreeMap<>();
        for (AccessEntry e : entries) {
            if (!isProviderEgress(e)) {
                continue;
            }
            Instant t = parseOrNull(e.startTime());
            if (t == null || t.isBefore(from) || !t.isBefore(to)) {
                continue;
            }
            providerRequests++;
            byPath.merge(e.path(), 1L, Long::sum);
        }
        long matched = Math.min(providerRequests, recordCount);
        long gaps = Math.max(0, providerRequests - recordCount);
        long recordsWithoutEnvoy = Math.max(0, recordCount - providerRequests);
        return new Reconciliation(providerRequests, recordCount, matched, gaps,
                recordsWithoutEnvoy, byPath, 0, 0, 0, providerRequests,
                gaps > 0 ? 1 : 0, Map.of(), 0, 0, 0, 0, Map.of(), 0,
                "Legacy count-based reconciliation overload; M10b report path uses request ids.");
    }

    /**
     * Three-ledger reconciliation. Envoy access entries match Gate Records by request id.
     * Flow entries are a network-ledger count/byte cross-check; v1 flow records do not
     * carry request ids, so flow-vs-Envoy discrepancies are counted by window.
     */
    public static Reconciliation reconcile(List<AccessEntry> entries, List<RecordRow> rows,
                                           List<FlowFeedReconciler.FlowEntry> flows,
                                           Set<String> providerDomains,
                                           String fromInclusive, String toExclusive) {
        Instant from = parseOrMin(fromInclusive);
        Instant to = parseOrMax(toExclusive);
        List<AccessEntry> providerEntries = new ArrayList<>();
        Map<String, Long> byPath = new TreeMap<>();
        for (AccessEntry e : entries) {
            if (!isProviderEgress(e)) {
                continue; // not forwarded to a Provider (e.g. /ready direct response)
            }
            Instant t = parseOrNull(e.startTime());
            // Compare as instants, not lexicographically: Envoy stamps millisecond
            // precision (…0.000Z) while window bounds and Record timestamps may not,
            // and string compare gets the fractional-second boundary wrong.
            if (t == null || t.isBefore(from) || !t.isBefore(to)) {
                continue; // unparseable or outside the window
            }
            providerEntries.add(e);
            byPath.merge(e.path(), 1L, Long::sum);
        }
        Map<String, AccessEntry> accessById = providerEntries.stream()
                .filter(e -> hasText(e.requestId()))
                .collect(Collectors.toMap(AccessEntry::requestId, e -> e, (a, b) -> a, HashMap::new));
        List<RecordRow> providerEgressRows = rows.stream()
                .filter(AccessLogReconciler::providerEgressRow)
                .toList();
        Map<String, RecordRow> recordsById = providerEgressRows.stream()
                .filter(r -> hasText(r.requestId()))
                .collect(Collectors.toMap(RecordRow::requestId, r -> r, (a, b) -> a, HashMap::new));

        long matched = 0;
        long gaps = 0;
        long unmatchedBytes = 0;
        Map<String, Long> failOpenBuckets = new TreeMap<>();
        for (AccessEntry e : providerEntries) {
            if (hasText(e.requestId()) && recordsById.containsKey(e.requestId())) {
                matched++;
            } else {
                gaps++;
                unmatchedBytes += Math.max(0, e.bytesReceived());
                String minute = minuteBucket(e.startTime());
                if (minute != null) {
                    failOpenBuckets.merge(minute, 1L, Long::sum);
                }
            }
        }
        long recordsWithoutEnvoy = 0;
        for (RecordRow row : providerEgressRows) {
            if (!hasText(row.requestId()) || !accessById.containsKey(row.requestId())) {
                recordsWithoutEnvoy++;
            }
        }

        var flowSummary = FlowFeedReconciler.summarize(flows, providerDomains, from, to);
        long flowWithoutEnvoy = Math.max(0, flowSummary.providerEvents() - providerEntries.size());
        long envoyWithoutFlow = Math.max(0, providerEntries.size() - flowSummary.providerEvents());

        ByteSums byteSums = byteSums(providerEgressRows, unmatchedBytes);
        String note = "Envoy and Record ledgers are matched by request id. "
                + "Fail-open minutes are distinct UTC minute buckets containing provider-bound "
                + "Envoy access entries with no matching Gate Record.";
        return new Reconciliation(providerEntries.size(), providerEgressRows.size(), matched, gaps,
                recordsWithoutEnvoy, byPath, flowSummary.providerEvents(), flowSummary.providerBytes(),
                flowWithoutEnvoy, envoyWithoutFlow, failOpenBuckets.size(), failOpenBuckets,
                byteSums.inspectedEgressBytes(), byteSums.providerEgressBytes(),
                byteSums.uninspectedEgressBytes(), byteSums.missingCounts(),
                flowSummary.providerFlowsByDestination(), flowSummary.unclassifiedEvents(), note);
    }

    private static boolean providerEgressRow(RecordRow row) {
        Long egressed = row.requestBytesEgressed();
        if (egressed != null) {
            // A completed zero-body request (for example Claude Code's HEAD auth
            // probe) is still Provider Egress. A zero-byte BLOCK is not.
            return egressed > 0 || !"BLOCK".equals(row.action());
        }
        return !"BLOCK".equals(row.action());
    }

    private static boolean isProviderEgress(AccessEntry e) {
        if (!PROVIDER_CLUSTER.equals(e.upstreamCluster())) {
            return false;
        }
        String details = e.responseCodeDetails();
        if (details == null || details.equals("via_upstream")) {
            return true;
        }
        // Streaming Agents may close the downstream SSE response after consuming the
        // answer. Envoy reports that response-side event as downstream_remote_disconnect
        // even though it already forwarded the body-bearing request to the Provider.
        // Requiring request bytes keeps zero-body local control requests out of the
        // Provider Egress ledger.
        return e.bytesReceived() > 0 && details.equals("downstream_remote_disconnect");
    }

    private static ByteSums byteSums(List<RecordRow> rows, long unmatchedBytes) {
        long inspected = 0;
        long egressed = unmatchedBytes;
        long missing = 0;
        for (RecordRow row : rows) {
            Long rowEgressed = row.requestBytesEgressed();
            Long rowInspected = row.requestBytesInspected();
            if (rowEgressed == null || rowInspected == null) {
                missing++;
                continue;
            }
            long safeEgressed = Math.max(0, rowEgressed);
            egressed += safeEgressed;
            inspected += Math.min(Math.max(0, rowInspected), safeEgressed);
        }
        return new ByteSums(inspected, egressed, Math.max(0, egressed - inspected), missing);
    }

    private record ByteSums(long inspectedEgressBytes, long providerEgressBytes,
                            long uninspectedEgressBytes, long missingCounts) {
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static String minuteBucket(String iso) {
        Instant t = parseOrNull(iso);
        if (t == null) {
            return null;
        }
        return DateTimeFormatter.ISO_INSTANT.format(t.truncatedTo(ChronoUnit.MINUTES)
                .atOffset(ZoneOffset.UTC));
    }

    private static Instant parseOrNull(String iso) {
        try {
            return Instant.parse(iso);
        } catch (Exception e) {
            return null;
        }
    }

    private static Instant parseOrMin(String iso) {
        Instant t = parseOrNull(iso);
        return t == null ? Instant.MIN : t;
    }

    private static Instant parseOrMax(String iso) {
        Instant t = parseOrNull(iso);
        return t == null ? Instant.MAX : t;
    }
}
