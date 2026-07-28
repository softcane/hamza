package ai.hamza.extproc;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Bounded, content-free memory of coached sessions. */
class CoachSessionTrackerTest {

    @Test
    void marksAndRecallsSessions() {
        CoachSessionTracker t = new CoachSessionTracker();
        assertThat(t.wasCoached("s1")).isFalse();
        t.markCoached("s1");
        assertThat(t.wasCoached("s1")).isTrue();
        assertThat(t.wasCoached("s2")).isFalse();
    }

    @Test
    void nullAndBlankSessionsAreIgnored() {
        CoachSessionTracker t = new CoachSessionTracker();
        t.markCoached(null);
        t.markCoached("  ");
        assertThat(t.wasCoached(null)).isFalse();
        assertThat(t.wasCoached("  ")).isFalse();
    }

    @Test
    void evictsBeyondCapButKeepsRecent() {
        CoachSessionTracker t = new CoachSessionTracker(2);
        t.markCoached("a");
        t.markCoached("b");
        t.markCoached("c"); // evicts eldest ("a")
        assertThat(t.wasCoached("c")).isTrue();
        assertThat(t.wasCoached("b")).isTrue();
        assertThat(t.wasCoached("a")).isFalse();
    }
}
