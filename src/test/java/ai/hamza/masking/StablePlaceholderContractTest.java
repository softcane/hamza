package ai.hamza.masking;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class StablePlaceholderContractTest {

    @Test
    void reusesWithinOneScopeButNotAcrossScopesOrAfterClosure() {
        AtomicInteger keys = new AtomicInteger();
        MaskScopeStore store = new MaskScopeStore(Clock.systemUTC(), Duration.ofMinutes(15),
                () -> key(keys.incrementAndGet()));

        String first = store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                "edm", "edm-customers", MaskingTestFixture.EMAIL);
        String repeated = store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                "edm", "edm-customers", MaskingTestFixture.EMAIL);
        String distinct = store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                "edm", "edm-customers", "rene.fixture@example.invalid");
        String anotherScope = store.placeholder("scope-2", PlaceholderFamily.EMAIL,
                "edm", "edm-customers", MaskingTestFixture.EMAIL);

        assertThat(repeated).isEqualTo(first);
        assertThat(distinct).isNotEqualTo(first);
        assertThat(anotherScope).isNotEqualTo(first);
        assertThat(first).matches("<EMAIL_[0-9]+>");

        store.close("scope-1");
        assertThat(store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                "edm", "edm-customers", MaskingTestFixture.EMAIL)).isNotEqualTo(first);
    }

    @Test
    void diagnosticRenderingContainsNoSourceFingerprintOrPlaceholderMapping() {
        MaskScopeStore store = new MaskScopeStore();
        store.placeholder("scope-1", PlaceholderFamily.SECRET,
                "secret", "fake-rule", MaskingTestFixture.SECRET);

        assertThat(store.toString())
                .doesNotContain(MaskingTestFixture.SECRET, "SECRET_", "fake-rule")
                .contains("activeScopes=1");
    }

    @Test
    void expiresScopesAndRejectsInvalidBoundsAndIdentifiers() {
        MutableClock clock = new MutableClock(Instant.parse("2026-07-15T00:00:00Z"));
        AtomicInteger keys = new AtomicInteger();
        MaskScopeStore store = new MaskScopeStore(clock, Duration.ofMinutes(1),
                () -> key(keys.incrementAndGet()));
        String first = store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                "edm", "rule", MaskingTestFixture.EMAIL);
        clock.now = clock.now.plusSeconds(30);
        assertThat(store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                "edm", "rule", MaskingTestFixture.EMAIL)).isEqualTo(first);
        clock.now = clock.now.plusSeconds(31);

        assertThat(store.activeScopes()).isZero();
        assertThat(store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                "edm", "rule", MaskingTestFixture.EMAIL)).isNotEqualTo(first);
        store.close(null);
        store.close("missing");

        assertThat(org.assertj.core.api.Assertions.catchThrowable(() ->
                new MaskScopeStore(clock, Duration.ZERO, () -> key(1))))
                .hasMessageContaining("TTL");
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() ->
                new MaskScopeStore(clock, Duration.ofMinutes(16), () -> key(1))))
                .hasMessageContaining("TTL");
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() ->
                new MaskScopeStore(clock, Duration.ofMinutes(1), () -> new byte[1])
                        .placeholder("scope-1", PlaceholderFamily.EMAIL,
                                "edm", "rule", MaskingTestFixture.EMAIL)))
                .hasMessageContaining("32 bytes");
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() ->
                store.placeholder("", PlaceholderFamily.EMAIL,
                        "edm", "rule", MaskingTestFixture.EMAIL)))
                .hasMessageContaining("scopeId");
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() ->
                store.placeholder("scope-1", null,
                        "edm", "rule", MaskingTestFixture.EMAIL)))
                .isInstanceOf(NullPointerException.class);
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() ->
                store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                        "bad detector", "rule", MaskingTestFixture.EMAIL)))
                .hasMessageContaining("detectorId");
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() ->
                store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                        "edm", "bad rule", MaskingTestFixture.EMAIL)))
                .hasMessageContaining("rule");
        assertThat(org.assertj.core.api.Assertions.catchThrowable(() ->
                store.placeholder("scope-1", PlaceholderFamily.EMAIL,
                        "edm", "rule", null)))
                .isInstanceOf(NullPointerException.class);
    }

    private static byte[] key(int value) {
        byte[] bytes = new byte[32];
        java.util.Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
