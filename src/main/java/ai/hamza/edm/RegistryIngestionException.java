package ai.hamza.edm;

/** Generic, content-free ingest error. Messages never contain CSV data. */
public final class RegistryIngestionException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public enum Kind {
        BAD_REQUEST,
        PAYLOAD_TOO_LARGE,
        DISABLED
    }

    private final Kind kind;
    private final String code;

    RegistryIngestionException(Kind kind, String code) {
        super(code);
        this.kind = kind;
        this.code = code;
    }

    public Kind kind() {
        return kind;
    }

    public String code() {
        return code;
    }
}
