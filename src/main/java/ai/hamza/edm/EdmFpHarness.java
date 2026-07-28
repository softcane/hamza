package ai.hamza.edm;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Measures Exact-Data-Match false positives over a benign corpus using the REAL
 * {@link EdmMatcher} — the number that gates promoting a registry to BLOCK
 * ("tune N and suppression until measured FP ≈ 0"). Runs entirely inside the
 * operator's boundary; output is content-free (paths + counts, never matched values).
 *
 * <p>Run in-image (no local JDK) via {@code scripts/edm-fp-harness.sh}.
 * The corpus is scanned in windows of the Gate's body cap so "would this window
 * block?" mirrors production scan-window semantics.
 */
public final class EdmFpHarness {

    private EdmFpHarness() {
    }

    /** Per-registry aggregate across all corpus windows. Content-free. */
    static final class RegistryStats {
        long windowsWithMatch;
        int maxDistinct;
        long wouldBlockWindows;
        final List<String> wouldBlockFiles = new ArrayList<>();
    }

    record Report(long files, long windows, long bytes, Map<String, RegistryStats> registries) {
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.err.println("usage: EdmFpHarness <registry-dir> <corpus-dir> [threshold] [window-bytes]");
            System.exit(2);
        }
        int threshold = args.length > 2 ? Integer.parseInt(args[2]) : 10;
        int windowBytes = args.length > 3 ? Integer.parseInt(args[3]) : 65_536;
        RegistryStore store = new RegistryStore(Path.of(args[0]));
        if (store.isEmpty()) {
            System.err.println("[edm-fp] no registries loaded from " + args[0]);
            System.exit(2);
        }
        Report report = run(store, Path.of(args[1]), threshold, windowBytes);
        System.out.printf("[edm-fp] corpus=%s files=%d windows=%d bytes=%d threshold=%d%n",
                args[1], report.files(), report.windows(), report.bytes(), threshold);
        boolean anyBlock = false;
        for (Map.Entry<String, RegistryStats> e : report.registries().entrySet()) {
            RegistryStats s = e.getValue();
            System.out.printf("[edm-fp] registry=%s windows_with_match=%d max_distinct=%d would_block=%d%n",
                    e.getKey(), s.windowsWithMatch, s.maxDistinct, s.wouldBlockWindows);
            s.wouldBlockFiles.stream().limit(10).forEach(f ->
                    System.out.println("[edm-fp]   would-block window in: " + f));
            anyBlock |= s.wouldBlockWindows > 0;
        }
        System.out.println(anyBlock
                ? "[edm-fp] VERDICT: would-block windows found — inspect the files above before promoting to BLOCK"
                : "[edm-fp] VERDICT: zero would-block windows — safe to promote at this threshold");
    }

    static Report run(RegistryStore store, Path corpus, int threshold, int windowBytes)
            throws IOException {
        EdmMatcher matcher = new EdmMatcher(store);
        Map<String, RegistryStats> stats = new LinkedHashMap<>();
        store.registries().forEach(r -> stats.put(r.name(), new RegistryStats()));
        long files = 0;
        long windows = 0;
        long bytes = 0;
        try (Stream<Path> walk = Files.walk(corpus)) {
            for (Path file : walk.filter(Files::isRegularFile)
                    .filter(p -> !p.toString().contains("/.git/")).sorted().toList()) {
                byte[] raw = Files.readAllBytes(file);
                if (raw.length == 0 || looksBinary(raw)) {
                    continue;
                }
                files++;
                bytes += raw.length;
                String text = new String(raw, StandardCharsets.UTF_8);
                for (int off = 0; off < text.length(); off += windowBytes) {
                    String window = text.substring(off, Math.min(text.length(), off + windowBytes));
                    windows++;
                    for (Map.Entry<String, Integer> m : matcher.match(window).entrySet()) {
                        RegistryStats s = stats.get(m.getKey());
                        s.windowsWithMatch++;
                        s.maxDistinct = Math.max(s.maxDistinct, m.getValue());
                        if (m.getValue() >= threshold) {
                            s.wouldBlockWindows++;
                            s.wouldBlockFiles.add(corpus.relativize(file) + " (distinct=" + m.getValue() + ")");
                        }
                    }
                }
            }
        }
        return new Report(files, windows, bytes, stats);
    }

    private static boolean looksBinary(byte[] raw) {
        int limit = Math.min(raw.length, 8192);
        for (int i = 0; i < limit; i++) {
            if (raw[i] == 0) {
                return true;
            }
        }
        return false;
    }
}
