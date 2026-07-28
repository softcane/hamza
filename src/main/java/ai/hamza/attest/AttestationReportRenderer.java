package ai.hamza.attest;

import java.util.List;
import java.util.Map;

/**
 * Hand-rolled HTML rendering for the attestation Receipt (no template library). Moved
 * out of {@link AttestationReporter} so report assembly and rendering are separate
 * concerns; {@code AttestationReporter} keeps a thin delegating {@code toHtml} for
 * callers in this package.
 */
final class AttestationReportRenderer {

    private AttestationReportRenderer() {
    }

    static String toHtml(ReportModel m) {
        var c = m.coverage();
        String chainClass = m.chain().ok() ? "ok" : "broken";
        String coverageClass = "VERIFIED".equals(c.status()) ? "ok" : "warn";
        StringBuilder sb = new StringBuilder(4096);
        sb.append("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
                .append("<title>Hamza Attestation Report</title>\n<style>\n")
                .append("body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1a1a1a;max-width:60rem}\n")
                .append("h1{font-size:1.5rem}h2{font-size:1.1rem;margin-top:2rem;border-bottom:1px solid #ddd;padding-bottom:.3rem}\n")
                .append("table{border-collapse:collapse;margin:.5rem 0}td,th{border:1px solid #ccc;padding:.3rem .6rem;text-align:left}\n")
                .append("th{background:#f4f4f4}.badge{display:inline-block;padding:.15rem .6rem;border-radius:.3rem;font-weight:600}\n")
                .append(".ok{background:#e4f5e4;color:#1a6b1a}.broken{background:#fce4e4;color:#a01414}.warn{background:#fdf3d8;color:#8a5a00}\n")
                .append(".muted{color:#666}code{font-family:ui-monospace,Menlo,monospace;font-size:.85em;word-break:break-all}\n")
                .append("</style></head><body>\n");
        sb.append("<h1>Hamza Attestation Report</h1>\n");
        sb.append("<p class=\"muted\">Content-free receipt: counts, rules, Actions, "
                + "hashes and timestamps only &mdash; never prompt text, secret values, or body content.</p>\n");
        sb.append("<table>\n")
                .append(row("Schema", esc(m.schemaVersion())))
                .append(row("Generated at", esc(m.generatedAt())))
                .append(row("Window", esc(m.windowFrom()) + " &rarr; " + esc(m.windowTo())))
                .append(row("Turns seen", String.valueOf(m.turnsSeen())))
                .append(row("Blocks", String.valueOf(m.blocks())))
                .append(row("Covered population", esc(m.coveredPopulation())))
                .append("</table>\n");

        sb.append("<h2>Chain verification</h2>\n");
        sb.append("<p><span class=\"badge ").append(chainClass).append("\">")
                .append(m.chain().ok() ? "OK" : "BROKEN").append("</span> ")
                .append("over ").append(m.chain().entries()).append(" entries. ")
                .append(esc(contentFreeChainDetail(m.chain()))).append("</p>\n");
        if (!m.chain().ok()) {
            sb.append("<p class=\"muted\">First broken link at seq ")
                    .append(m.chain().firstBrokenSeq()).append(".</p>\n");
        }
        sb.append("<p class=\"muted\">Chain head: <code>")
                .append(esc(safeHash(m.chain().headHash())))
                .append("</code></p>\n");
        if (m.chain().legacyRows() > 0) {
            sb.append("<p class=\"muted\">").append(m.chain().legacyRows())
                    .append(" row(s) predate the chain migration and are unchained "
                            + "(not covered by this verification).</p>\n");
        }

        sb.append("<h2>Posture &amp; config fingerprint</h2>\n");
        sb.append(mapTable("Posture", "Turns", m.postures()));
        sb.append(mapTable("Config fingerprint", "Turns", m.configFingerprints()));

        sb.append("<h2>Findings by rule</h2>\n").append(mapTable("Rule", "Count", m.findingsByRule()));
        sb.append("<h2>Findings by action</h2>\n").append(mapTable("Action", "Count", m.findingsByAction()));

        var continuation = m.safeContinuation();
        sb.append("<h2>Safe Continuation evidence</h2>\n")
                .append("<table>\n")
                .append(row("Recovery scopes", String.valueOf(continuation.recoveryScopes())))
                .append(row("Eligible", String.valueOf(continuation.eligible())))
                .append(row("Attempted", String.valueOf(continuation.attempted())))
                .append(row("Delivered", String.valueOf(continuation.delivered())))
                .append(row("Rejected", String.valueOf(continuation.rejected())))
                .append(row("Failed closed", String.valueOf(continuation.failedClosed())))
                .append(row("Completed outcomes", String.valueOf(continuation.completed())))
                .append(row("Failed outcomes", String.valueOf(continuation.failed())))
                .append(row("Human fallback outcomes", String.valueOf(continuation.fallback())))
                .append(row("Source Block Turns", String.valueOf(continuation.sourceBlockTurns())))
                .append(row("Source Mask Turns", String.valueOf(continuation.sourceMaskTurns())))
                .append(row("Derived Flag Turns", String.valueOf(continuation.derivedFlagTurns())))
                .append(row("Linked source/derived pairs", String.valueOf(continuation.linkedPairs())))
                .append(row("Original bytes withheld", String.valueOf(continuation.originalBytesWithheld())))
                .append(row("Transformed bytes inspected", String.valueOf(continuation.transformedBytesInspected())))
                .append(row("Transformed bytes Egressed", String.valueOf(continuation.transformedBytesEgressed())))
                .append(row("Recovery Outcome integrity", esc(continuation.outcomeIntegrity().status())))
                .append("</table>\n")
                .append(mapTable("Agent", "Continuation Turns", continuation.turnsByAgent()))
                .append(mapTable("Provider", "Continuation Turns", continuation.turnsByProvider()))
                .append(mapTable("Outcome Agent version", "Count",
                        continuation.outcomesByAgentVersion()))
                .append(mapTable("Outcome status", "Count", continuation.outcomesByStatus()))
                .append(mapTable("Recipe version", "Source Turns", continuation.recipeVersions()))
                .append(mapTable("Workflow profile version", "Source Turns",
                        continuation.workflowProfileVersions()))
                .append("<h3>Evidence coverage gaps</h3>\n")
                .append(mapTable("Fixed gap class", "Count", continuation.coverageGaps()));

        sb.append("<h2>EDM events</h2>\n").append(edmTable(m.edmEvents()));

        sb.append("<h2>Registry staleness</h2>\n");
        sb.append("<p><span class=\"badge ")
                .append("VERIFIED".equals(m.registryStaleness().status()) ? "ok" : "warn")
                .append("\">").append(esc(m.registryStaleness().status())).append("</span></p>\n");
        sb.append("<p>").append(esc(m.registryStaleness().note())).append("</p>\n");
        sb.append(registryTable(m.registryStaleness().registries()));

        sb.append("<h2>Coverage reconciliation</h2>\n");
        sb.append("<p><span class=\"badge ").append(coverageClass).append("\">coverage: ")
                .append(esc(c.status())).append("</span></p>\n");
        sb.append("<p>").append(esc(c.note())).append("</p>\n");
        if (c.providerRequests() != null) {
            sb.append("<table>\n")
                    .append(row("Flow provider events", String.valueOf(c.flowProviderEvents())))
                    .append(row("Flow provider bytes", String.valueOf(c.flowBytes())))
                    .append(row("Envoy provider-bound requests", String.valueOf(c.providerRequests())))
                    .append(row("Gate provider-egress Records", String.valueOf(c.records())))
                    .append(row("Matched", String.valueOf(c.recordsMatched())))
                    .append(row("Coverage gaps (provider requests without a Record)",
                            String.valueOf(c.coverageGaps())))
                    .append(row("Records without Envoy evidence",
                            String.valueOf(c.recordsWithoutEnvoyEvidence())))
                    .append(row("Flow events without Envoy evidence",
                            String.valueOf(c.flowWithoutEnvoyEvidence())))
                    .append(row("Envoy requests without flow evidence",
                            String.valueOf(c.envoyWithoutFlowEvidence())))
                    .append(row("Fail-open uninspected minutes",
                            String.valueOf(c.failOpenUninspectedMinutes())))
                    .append(row("Unexplained Provider requests/events",
                            value(AttestationReporter.unexplainedProviderRequests(c))))
                    .append(row("Zero unexplained Provider requests",
                            String.valueOf("VERIFIED".equals(c.ledgerStatus())
                                    && Long.valueOf(0).equals(
                                            AttestationReporter.unexplainedProviderRequests(c)))))
                    .append(row("Coverage",
                            c.coveragePercent() == null ? "N/A" : String.format("%.2f%%", c.coveragePercent())))
                    .append("</table>\n");
            sb.append(mapTable("Provider path", "Requests", c.providerRequestsByPath()));
            sb.append(mapTable("Fail-open minute", "Requests", c.failOpenRequestsByMinute()));
            sb.append(mapTable("Provider flow destination", "Flows", c.providerFlowsByDestination()));
        }

        var b = m.inspectedBytes();
        sb.append("<h2>Inspected bytes</h2>\n");
        sb.append("<p><span class=\"badge ")
                .append("VERIFIED".equals(b.status()) ? "ok" : "warn")
                .append("\">").append(esc(b.status())).append("</span></p>\n");
        sb.append("<table>\n")
                .append(row("Inspected provider-egress bytes", value(b.inspectedBytes())))
                .append(row("Provider egress bytes", value(b.egressedBytes())))
                .append(row("Flow provider bytes", value(b.flowBytes())))
                .append(row("Uninspected egress bytes", value(b.uninspectedBytes())))
                .append(row("Inspected-byte %", b.inspectedPercent() == null ? "N/A"
                        : String.format("%.2f%%", b.inspectedPercent())))
                .append(row("Records missing byte counts", value(b.recordsMissingByteCounts())))
                .append("</table>\n");
        sb.append("<p>").append(esc(b.note())).append("</p>\n");

        sb.append("</body></html>\n");
        return sb.toString();
    }

    private static String row(String k, String v) {
        return "<tr><th>" + esc(k) + "</th><td>" + v + "</td></tr>";
    }

    private static String mapTable(String keyHeader, String valHeader, Map<String, Long> data) {
        if (data == null || data.isEmpty()) {
            return "<p class=\"muted\">(none)</p>\n";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("<table>\n<tr><th>").append(esc(keyHeader)).append("</th><th>")
                .append(esc(valHeader)).append("</th></tr>\n");
        for (Map.Entry<String, Long> e : data.entrySet()) {
            sb.append("<tr><td><code>").append(esc(e.getKey())).append("</code></td><td>")
                    .append(e.getValue()).append("</td></tr>\n");
        }
        sb.append("</table>\n");
        return sb.toString();
    }

    private static String edmTable(Map<String, ReportModel.EdmEventSummary> data) {
        if (data == null || data.isEmpty()) {
            return "<p class=\"muted\">(none)</p>\n";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("<table>\n<tr><th>Registry</th><th>Events</th><th>Distinct matches</th>")
                .append("<th>Block events</th><th>Flag events</th><th>Note</th></tr>\n");
        for (ReportModel.EdmEventSummary e : data.values()) {
            sb.append("<tr><td><code>").append(esc(e.registry())).append("</code></td><td>")
                    .append(e.events()).append("</td><td>").append(value(e.distinctMatches()))
                    .append("</td><td>").append(e.blockEvents()).append("</td><td>")
                    .append(e.flagEvents()).append("</td><td>").append(esc(e.note()))
                    .append("</td></tr>\n");
        }
        sb.append("</table>\n");
        return sb.toString();
    }

    private static String registryTable(List<ReportModel.RegistryStalenessEntry> data) {
        if (data == null || data.isEmpty()) {
            return "<p class=\"muted\">(none)</p>\n";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("<table>\n<tr><th>Registry</th><th>Distinct fingerprints</th>")
                .append("<th>Source timestamp</th><th>Age seconds</th><th>Source</th></tr>\n");
        for (ReportModel.RegistryStalenessEntry e : data) {
            sb.append("<tr><td><code>").append(esc(e.registry())).append("</code></td><td>")
                    .append(e.distinctFingerprints()).append("</td><td>")
                    .append(esc(e.sourceTimestamp())).append("</td><td>")
                    .append(value(e.ageSeconds())).append("</td><td>")
                    .append(esc(e.source())).append("</td></tr>\n");
        }
        sb.append("</table>\n");
        return sb.toString();
    }

    private static String value(Long value) {
        return value == null ? "N/A" : String.valueOf(value);
    }

    static String safeHash(String hash) {
        return hash != null && hash.matches("[0-9a-f]{64}") ? hash : null;
    }

    static String contentFreeChainDetail(ChainVerifier.Result chain) {
        if (chain.ok()) {
            return chain.legacyRows() > 0
                    ? "ok; pre-migration rows are unchained by design" : "ok";
        }
        String detail = chain.detail();
        if (detail == null) {
            return "chain verification failed";
        }
        if (detail.startsWith("seq gap")) {
            return "seq gap";
        }
        if (detail.startsWith("prev_hash mismatch")) {
            return "prev_hash mismatch";
        }
        if (detail.startsWith("entry_hash mismatch")) {
            return "entry_hash mismatch";
        }
        if (detail.startsWith("unsupported hash_version")) {
            return "unsupported hash_version";
        }
        return "chain verification failed";
    }

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
