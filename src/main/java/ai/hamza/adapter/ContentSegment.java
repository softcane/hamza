package ai.hamza.adapter;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * One transient, decoded text value from a Provider-approved content field.
 *
 * <p>The identifier is Adapter-issued and bounded. The text is intentionally available to
 * the in-boundary matcher, but {@link #toString()} never renders it.
 */
public final class ContentSegment {

    private static final Pattern ID = Pattern.compile("[a-z][a-z0-9-]{0,63}");

    private final String id;
    private final String text;

    public ContentSegment(String id, String text) {
        if (id == null || !ID.matcher(id).matches()) {
            throw new IllegalArgumentException("invalid content segment id");
        }
        this.id = id;
        this.text = Objects.requireNonNull(text, "text");
    }

    public String id() {
        return id;
    }

    public String text() {
        return text;
    }

    @Override
    public String toString() {
        return "ContentSegment[id=" + id + ", chars=" + text.length() + "]";
    }
}
