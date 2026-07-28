package ai.hamza.masking;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Volatile 15-minute Mask Scope state. It retains only a random HMAC key, scoped
 * Fingerprints, counters, and Placeholder identifiers; source values never enter a map.
 */
public final class MaskScopeStore {

    static final Duration DEFAULT_TTL = Duration.ofMinutes(15);
    private static final String HMAC = "HmacSHA256";
    private static final int KEY_BYTES = 32;
    private static final long COUNTER_RANGE = 900_000_000L;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Clock clock;
    private final Duration ttl;
    private final Supplier<byte[]> keySupplier;
    private final Map<String, Scope> scopes = new HashMap<>();

    public MaskScopeStore() {
        this(Clock.systemUTC(), DEFAULT_TTL, MaskScopeStore::randomKey);
    }

    MaskScopeStore(Clock clock, Duration ttl, Supplier<byte[]> keySupplier) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.ttl = Objects.requireNonNull(ttl, "ttl");
        this.keySupplier = Objects.requireNonNull(keySupplier, "keySupplier");
        if (ttl.isZero() || ttl.isNegative() || ttl.compareTo(DEFAULT_TTL) > 0) {
            throw new IllegalArgumentException("Mask Scope TTL must be within 15 minutes");
        }
    }

    public synchronized String placeholder(String scopeId, PlaceholderFamily family,
                                           String detectorId, String rule,
                                           String sourceValue) {
        requireId(scopeId, "scopeId");
        Objects.requireNonNull(family, "family");
        requireId(detectorId, "detectorId");
        requireId(rule, "rule");
        Objects.requireNonNull(sourceValue, "sourceValue");
        Instant now = clock.instant();
        expire(now);
        Scope scope = scopes.computeIfAbsent(scopeId, ignored -> newScope(now));
        String fingerprint = hex(hmac(scope.key,
                detectorId + '\u001f' + rule + '\u001f' + sourceValue));
        return scope.placeholders.computeIfAbsent(fingerprint, ignored -> {
            long identifier = scope.next.compute(family,
                    (unused, current) -> current == null
                            ? initialCounter(scope.key, family) : current + 1L);
            return family.render(identifier);
        });
    }

    public synchronized void close(String scopeId) {
        if (scopeId != null) {
            Scope removed = scopes.remove(scopeId);
            if (removed != null) {
                Arrays.fill(removed.key, (byte) 0);
                removed.placeholders.clear();
                removed.next.clear();
            }
        }
    }

    synchronized int activeScopes() {
        expire(clock.instant());
        return scopes.size();
    }

    private Scope newScope(Instant now) {
        byte[] key = keySupplier.get();
        if (key == null || key.length != KEY_BYTES) {
            throw new IllegalStateException("Mask Scope key must be 32 bytes");
        }
        return new Scope(key.clone(), now.plus(ttl));
    }

    private void expire(Instant now) {
        Iterator<Map.Entry<String, Scope>> entries = scopes.entrySet().iterator();
        while (entries.hasNext()) {
            Scope scope = entries.next().getValue();
            if (!now.isBefore(scope.expiresAt)) {
                Arrays.fill(scope.key, (byte) 0);
                scope.placeholders.clear();
                scope.next.clear();
                entries.remove();
            }
        }
    }

    private static long initialCounter(byte[] key, PlaceholderFamily family) {
        byte[] digest = hmac(key, "counter\u001f" + family.name());
        long value = 0;
        for (int i = 0; i < Long.BYTES; i++) {
            value = (value << 8) | Byte.toUnsignedLong(digest[i]);
        }
        return 1L + Long.remainderUnsigned(value, COUNTER_RANGE);
    }

    private static byte[] hmac(byte[] key, String value) {
        try {
            Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(key, HMAC));
            return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    private static byte[] randomKey() {
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(key);
        return key;
    }

    private static String hex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    private static void requireId(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 128
                || !value.matches("[A-Za-z0-9][A-Za-z0-9._:-]*")) {
            throw new IllegalArgumentException(name + " must be a bounded identifier");
        }
    }

    @Override
    public synchronized String toString() {
        return "MaskScopeStore[activeScopes=" + scopes.size() + ']';
    }

    private static final class Scope {
        private final byte[] key;
        private final Instant expiresAt;
        private final Map<String, String> placeholders = new HashMap<>();
        private final EnumMap<PlaceholderFamily, Long> next =
                new EnumMap<>(PlaceholderFamily.class);

        private Scope(byte[] key, Instant expiresAt) {
            this.key = key;
            this.expiresAt = expiresAt;
        }
    }
}
