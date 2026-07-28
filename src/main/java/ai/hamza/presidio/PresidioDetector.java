package ai.hamza.presidio;

import ai.hamza.adapter.ContentSegment;
import ai.hamza.policy.DetectionReason;
import ai.hamza.policy.DetectionStatus;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Runs the pinned in-boundary Analyzer over every decoded segment inside one shared
 * deadline. Any gap — timeout, bad response, excess output, invalid offset, or a
 * missing window — makes the run incomplete so the managed Turn fails safely.
 *
 * <p>Presidio reports Python string offsets, which are Unicode code points. They are
 * carried through unchanged: the Mask Planner also works in code points.
 */
public final class PresidioDetector {

    public static final String DETECTOR_ID = "presidio";
    public static final int WINDOW_CODE_POINTS = 4_096;
    public static final int WINDOW_OVERLAP_CODE_POINTS = 256;
    public static final int MAX_TURN_FINDINGS = 2_048;
    /** M3-evaluated budget for a Turn no larger than one Analyzer request. */
    public static final Duration SHARED_DEADLINE = Duration.ofMillis(1_000);
    /** Large Turns receive one base budget per request-sized body slice, up to this cap. */
    public static final Duration MAX_SHARED_DEADLINE = Duration.ofSeconds(16);

    private final PresidioClient client;
    private final PresidioProfile profile;

    public PresidioDetector(PresidioClient client, PresidioProfile profile) {
        this.client = Objects.requireNonNull(client, "client");
        this.profile = Objects.requireNonNull(profile, "profile");
    }

    public PresidioProfile profile() {
        return profile;
    }

    /**
     * Inspects every Provider-visible segment.
     *
     * @param segments decoded Adapter segments for one managed Turn
     * @return a complete run with exact code-point Findings, or a bounded gap
     */
    public PresidioScan scan(List<ContentSegment> segments) {
        List<ContentSegment> safe = segments == null ? List.of() : List.copyOf(segments);
        long receivedBytes = safe.stream().mapToLong(segment ->
                segment.text().getBytes(StandardCharsets.UTF_8).length).sum();
        long started = System.nanoTime();
        Duration deadline = sharedDeadline(receivedBytes);

        List<Window> windows = new ArrayList<>();
        for (ContentSegment segment : safe) {
            windows.addAll(windows(segment));
        }
        if (windows.isEmpty()) {
            return new PresidioScan(DetectionStatus.COMPLETE, Optional.empty(), List.of(),
                    safe.size(), safe.size(), receivedBytes, receivedBytes,
                    elapsedMicros(started));
        }

        List<List<PresidioClient.RawFinding>> answers;
        try {
            answers = client.analyze(windows.stream().map(Window::text).toList(),
                    profile.enabledEntities(), profile.minimumThreshold(), profile.language(),
                    remaining(started, deadline));
        } catch (PresidioGapException gap) {
            return gap(gap.reason(), safe.size(), receivedBytes, started);
        }
        if (answers.size() != windows.size()) {
            return gap(DetectionReason.BAD_RESPONSE, safe.size(), receivedBytes, started);
        }
        if (remaining(started, deadline).isZero()
                || remaining(started, deadline).isNegative()) {
            return gap(DetectionReason.TIMEOUT, safe.size(), receivedBytes, started);
        }

        Map<String, PresidioFinding> unique = new LinkedHashMap<>();
        for (int index = 0; index < windows.size(); index++) {
            Window window = windows.get(index);
            for (PresidioClient.RawFinding raw : answers.get(index)) {
                if (!profile.enabled(raw.entity())
                        || raw.score() < profile.threshold(raw.entity())) {
                    continue;
                }
                if (raw.start() < 0 || raw.end() <= raw.start()
                        || raw.end() > window.codePoints()) {
                    return gap(DetectionReason.BAD_RESPONSE, safe.size(), receivedBytes,
                            started);
                }
                int start = window.start() + raw.start();
                int end = window.start() + raw.end();
                if (end > window.segmentCodePoints()) {
                    return gap(DetectionReason.BAD_RESPONSE, safe.size(), receivedBytes,
                            started);
                }
                PresidioFinding finding = new PresidioFinding(raw.entity(), window.segmentId(),
                        start, end, raw.score());
                unique.putIfAbsent(key(finding), finding);
                if (unique.size() > MAX_TURN_FINDINGS) {
                    return gap(DetectionReason.OUTPUT_LIMIT, safe.size(), receivedBytes,
                            started);
                }
            }
        }
        return new PresidioScan(DetectionStatus.COMPLETE, Optional.empty(),
                List.copyOf(unique.values()), safe.size(), safe.size(), receivedBytes,
                receivedBytes, elapsedMicros(started));
    }

    private static String key(PresidioFinding finding) {
        return finding.segmentId() + '\u001f' + finding.entity() + '\u001f'
                + finding.start() + '\u001f' + finding.end();
    }

    private static List<Window> windows(ContentSegment segment) {
        String text = segment.text();
        int codePoints = text.codePointCount(0, text.length());
        if (codePoints == 0) {
            return List.of();
        }
        int step = WINDOW_CODE_POINTS - WINDOW_OVERLAP_CODE_POINTS;
        List<Window> windows = new ArrayList<>();
        int start = 0;
        while (start < codePoints) {
            int end = Math.min(start + WINDOW_CODE_POINTS, codePoints);
            int charStart = text.offsetByCodePoints(0, start);
            int charEnd = text.offsetByCodePoints(0, end);
            windows.add(new Window(segment.id(), start, text.substring(charStart, charEnd),
                    end - start, codePoints));
            if (end == codePoints) {
                break;
            }
            start += step;
        }
        return windows;
    }

    static Duration sharedDeadline(long receivedBytes) {
        long slices = Math.max(1L,
                Math.ceilDiv(Math.max(0L, receivedBytes), PresidioClient.MAX_REQUEST_BYTES));
        long cappedSlices = Math.min(slices,
                MAX_SHARED_DEADLINE.dividedBy(SHARED_DEADLINE));
        return SHARED_DEADLINE.multipliedBy(cappedSlices);
    }

    private static Duration remaining(long started, Duration deadline) {
        return deadline.minusNanos(System.nanoTime() - started);
    }

    private static PresidioScan gap(DetectionReason reason, int segments, long bytes,
                                    long started) {
        return new PresidioScan(DetectionStatus.INCOMPLETE, Optional.of(reason), List.of(),
                segments, 0, bytes, 0, elapsedMicros(started));
    }

    private static long elapsedMicros(long started) {
        return Math.max(0, (System.nanoTime() - started) / 1_000L);
    }

    private record Window(String segmentId, int start, String text, int codePoints,
                          int segmentCodePoints) { }
}
