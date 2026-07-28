package ai.hamza.extproc;

import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bounded, content-free memory of which sessions have already been coached (Blocked with
 * a Coach) in this process. It holds only the session id — the same identifier
 * the Record already carries — never any inspected content. Used to escalate an evasive
 * retry: after a coach in a session, a later same-session request that carries newly
 * re-encoded high-entropy content is a hard Block (the coach explicitly forbade this).
 *
 * <p>Bounded by an LRU cap so a long-lived Gate cannot accumulate unbounded session state;
 * eviction of an old session merely forgets that it was coached (fail-open — at worst a
 * later evasive retry is treated as a first offence).
 */
@Component
public class CoachSessionTracker {

    static final int DEFAULT_MAX_SESSIONS = 10_000;

    private final Map<String, Long> coachedAt;

    public CoachSessionTracker() {
        this(DEFAULT_MAX_SESSIONS);
    }

    CoachSessionTracker(int maxSessions) {
        int cap = maxSessions > 0 ? maxSessions : DEFAULT_MAX_SESSIONS;
        this.coachedAt = Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
                return size() > cap;
            }
        });
    }

    /** Record that {@code sessionId} has been coached. No-op for a null/blank session. */
    void markCoached(String sessionId) {
        if (sessionId != null && !sessionId.isBlank()) {
            coachedAt.put(sessionId, System.nanoTime());
        }
    }

    /** True if this session has already received a coach in this process. */
    boolean wasCoached(String sessionId) {
        return sessionId != null && !sessionId.isBlank() && coachedAt.containsKey(sessionId);
    }
}
