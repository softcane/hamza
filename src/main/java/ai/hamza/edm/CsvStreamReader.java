package ai.hamza.edm;

import java.io.IOException;
import java.io.PushbackReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

import static ai.hamza.edm.RegistryIngestionException.Kind.BAD_REQUEST;
import static ai.hamza.edm.RegistryIngestionException.Kind.PAYLOAD_TOO_LARGE;

/**
 * Small streaming CSV reader for the admin ingest surface. It keeps only the current
 * row in memory and enforces explicit row/field caps; malformed input fails with
 * content-free error codes.
 */
final class CsvStreamReader {

    static final int DEFAULT_MAX_ROW_CHARS = 1_048_576;
    static final int DEFAULT_MAX_FIELD_CHARS = 262_144;

    private final PushbackReader in;
    private final int maxRowChars;
    private final int maxFieldChars;

    CsvStreamReader(Reader in, int maxRowChars, int maxFieldChars) {
        this.in = new PushbackReader(in, 1);
        this.maxRowChars = maxRowChars;
        this.maxFieldChars = maxFieldChars;
    }

    List<String> readRow() throws IOException {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean atStartOfField = true;
        boolean inQuotes = false;
        boolean afterQuote = false;
        int rowChars = 0;

        while (true) {
            int ch = in.read();
            if (ch == -1) {
                if (inQuotes) {
                    throw badCsv();
                }
                if (rowChars == 0 && fields.isEmpty() && field.isEmpty()) {
                    return null;
                }
                fields.add(field.toString());
                return fields;
            }
            rowChars++;
            if (rowChars > maxRowChars) {
                throw tooLarge("csv-row-too-large");
            }
            char c = (char) ch;

            if (inQuotes) {
                if (c == '"') {
                    inQuotes = false;
                    afterQuote = true;
                } else {
                    append(field, c);
                }
                continue;
            }

            if (afterQuote) {
                if (c == '"') {
                    append(field, c);
                    inQuotes = true;
                    afterQuote = false;
                } else if (c == ',') {
                    fields.add(field.toString());
                    field.setLength(0);
                    atStartOfField = true;
                    afterQuote = false;
                } else if (isLineEnd(c)) {
                    consumeLfAfterCr(c);
                    fields.add(field.toString());
                    return fields;
                } else {
                    throw badCsv();
                }
                continue;
            }

            if (atStartOfField && c == '"') {
                inQuotes = true;
                atStartOfField = false;
            } else if (c == ',') {
                fields.add(field.toString());
                field.setLength(0);
                atStartOfField = true;
            } else if (isLineEnd(c)) {
                consumeLfAfterCr(c);
                fields.add(field.toString());
                return fields;
            } else {
                append(field, c);
                atStartOfField = false;
            }
        }
    }

    private void append(StringBuilder field, char c) {
        field.append(c);
        if (field.length() > maxFieldChars) {
            throw tooLarge("csv-field-too-large");
        }
    }

    private void consumeLfAfterCr(char c) throws IOException {
        if (c != '\r') {
            return;
        }
        int next = in.read();
        if (next != -1 && next != '\n') {
            in.unread(next);
        }
    }

    private static boolean isLineEnd(char c) {
        return c == '\n' || c == '\r';
    }

    private static RegistryIngestionException badCsv() {
        return new RegistryIngestionException(BAD_REQUEST, "malformed-csv");
    }

    private static RegistryIngestionException tooLarge(String code) {
        return new RegistryIngestionException(PAYLOAD_TOO_LARGE, code);
    }
}
