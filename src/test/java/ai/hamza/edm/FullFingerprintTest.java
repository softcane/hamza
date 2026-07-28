package ai.hamza.edm;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class FullFingerprintTest {

    private static final String HEX = "00112233445566778899aabbccddeeff"
            + "ffeeddccbbaa99887766554433221100";

    @Test
    void parsesAndRendersExactlyThirtyTwoBytes() {
        FullFingerprint fingerprint = FullFingerprint.parseHex(HEX);

        assertThat(fingerprint.toHex()).isEqualTo(HEX);
        assertThat(FullFingerprint.parseHex(HEX)).isEqualTo(fingerprint);
        assertThat(fingerprint.hashCode()).isEqualTo(FullFingerprint.parseHex(HEX).hashCode());
        assertThat(fingerprint.toString()).isEqualTo("FullFingerprint[redacted]")
                .doesNotContain(HEX);
    }

    @Test
    void rejectsWrongWidthUppercaseAndNonHexInput() {
        assertThatIllegalArgumentException().isThrownBy(() -> FullFingerprint.parseHex("00"));
        assertThatIllegalArgumentException().isThrownBy(() -> FullFingerprint.parseHex(HEX.toUpperCase()));
        assertThatIllegalArgumentException().isThrownBy(() -> FullFingerprint.parseHex("g".repeat(64)));
    }

    @Test
    void exposesNoRawByteArrayAndDefensivelyCopiesConstructionInput() {
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) 0x2a);
        FullFingerprint fingerprint = FullFingerprint.fromDigest(digest);
        digest[0] = 0;

        assertThat(fingerprint.toHex()).isEqualTo("2a".repeat(32));
        assertThat(Arrays.stream(FullFingerprint.class.getDeclaredMethods())
                .map(Method::getReturnType))
                .doesNotContain(byte[].class);
    }

    @Test
    void fingerprinterKeepsTheCompleteHmacDigest() {
        byte[] salt = "01234567890123456789012345678901".getBytes();

        assertThat(Fingerprinter.fullFingerprint(salt, "fake001@example-corp.test").toHex())
                .hasSize(64)
                .isEqualTo("69e1becec3c93be3a94e4dec52f6f1cd"
                        + "927d85d06858647dd175e4d640efe2a6");
    }
}
