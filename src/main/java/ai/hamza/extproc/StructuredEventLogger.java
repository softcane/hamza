package ai.hamza.extproc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.spi.LoggingEventBuilder;

import java.util.Map;
import java.util.Set;

/** Allowlisted structured logging boundary; request and response content cannot enter it. */
final class StructuredEventLogger {

    enum Event {
        TRANSPORT_REQUEST("transport.request"),
        TRANSPORT_RESPONSE("transport.response"),
        TRANSPORT_ERROR("transport.error"),
        MASK_PLANNED("mask.planned"),
        MASK_APPLIED("mask.applied"),
        MASK_FAILED("mask.failed"),
        DETECTOR_COMPLETED("detector.completed"),
        DETECTOR_GAP("detector.gap"),
        RECORD_COMMITTED("record.committed"),
        RECORD_FAILED("record.failed"),
        EGRESS_RELEASED("egress.released"),
        EGRESS_BLOCKED("egress.blocked");

        private final String id;

        Event(String id) {
            this.id = id;
        }

        String id() {
            return id;
        }
    }

    enum Field {
        TURN_ID("turn_id"),
        PROVIDER("provider"),
        AGENT("agent"),
        ACTION("action"),
        STATUS("status"),
        DETECTOR("detector"),
        REASON("reason"),
        BYTES("bytes"),
        COUNT("count"),
        DURATION_MICROS("duration_micros"),
        END_OF_STREAM("end_of_stream");

        private final String key;

        Field(String key) {
            this.key = key;
        }
    }

    private static final Set<String> PROVIDERS = Set.of("openai", "anthropic", "unknown", "none");
    private static final Set<String> AGENTS = Set.of("codex", "claude-code", "unknown");

    private final Logger logger;

    private StructuredEventLogger(Class<?> owner) {
        this.logger = LoggerFactory.getLogger(owner);
    }

    static StructuredEventLogger forClass(Class<?> owner) {
        return new StructuredEventLogger(owner);
    }

    void info(Event event, Map<Field, ?> fields) {
        write(logger.atInfo(), event, fields);
    }

    void warn(Event event, Map<Field, ?> fields) {
        write(logger.atWarn(), event, fields);
    }

    void debug(Event event, Map<Field, ?> fields) {
        write(logger.atDebug(), event, fields);
    }

    private static void write(LoggingEventBuilder builder, Event event, Map<Field, ?> fields) {
        if (fields != null) {
            fields.forEach((field, value) -> builder.addKeyValue(field.key, safe(field, value)));
        }
        builder.log(event.id);
    }

    private static Object safe(Field field, Object value) {
        if (value instanceof Number || value instanceof Boolean || value instanceof Enum<?>) {
            return value;
        }
        if (!(value instanceof String text) || text.length() > 128) {
            throw new IllegalArgumentException("unbounded structured log value");
        }
        return switch (field) {
            case PROVIDER -> requireMember(text, PROVIDERS, field);
            case AGENT -> requireMember(text, AGENTS, field);
            case TURN_ID -> requireMatch(text, "[0-9a-f-]{36}", field);
            case STATUS, DETECTOR, REASON, ACTION ->
                    requireMatch(text, "[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", field);
            case BYTES, COUNT, DURATION_MICROS, END_OF_STREAM ->
                    throw new IllegalArgumentException("numeric structured log field required");
        };
    }

    private static String requireMember(String value, Set<String> allowed, Field field) {
        if (!allowed.contains(value)) {
            throw new IllegalArgumentException("unapproved " + field.key);
        }
        return value;
    }

    private static String requireMatch(String value, String pattern, Field field) {
        if (!value.matches(pattern)) {
            throw new IllegalArgumentException("unapproved " + field.key);
        }
        return value;
    }
}
