package ai.hamza.scanner;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/** Loads the checked-in scanner fixtures (fake/example secrets only) from the classpath. */
final class ScannerFixtures {

    private ScannerFixtures() {
    }

    /** A fixture Egress request body from {@code scanner/bodies/<name>}. */
    static String body(String name) {
        return read("/scanner/bodies/" + name);
    }

    /** A checked-in Oracle JSON report from {@code scanner/oracle-reports/<name>}. */
    static String oracleReport(String name) {
        return read("/scanner/oracle-reports/" + name);
    }

    private static String read(String resource) {
        try (InputStream in = ScannerFixtures.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalArgumentException("missing fixture: " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
