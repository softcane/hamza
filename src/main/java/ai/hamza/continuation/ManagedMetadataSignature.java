package ai.hamza.continuation;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;

/** Canonical HMAC for trusted managed-Agent metadata; contains no request content. */
public final class ManagedMetadataSignature {

    private static final List<String> ORDER = List.of(
            ManagedMetadataVerifier.RECOVERY_ID,
            ManagedMetadataVerifier.PROFILE_ID,
            ManagedMetadataVerifier.PROFILE_VERSION,
            ManagedMetadataVerifier.AGENT,
            ManagedMetadataVerifier.PROVIDER,
            ManagedMetadataVerifier.MODEL,
            ManagedMetadataVerifier.ADAPTER_WIRE_VERSION,
            ManagedMetadataVerifier.ISSUED_AT);

    private ManagedMetadataSignature() {
    }

    public static String sign(Map<String, String> fields, byte[] key) {
        if (key == null || key.length < 16) {
            throw new IllegalArgumentException("managed metadata key is too short");
        }
        StringBuilder canonical = new StringBuilder("hamza-managed/v1\n");
        for (String name : ORDER) {
            String value = fields.get(name);
            if (value == null || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
                throw new IllegalArgumentException("incomplete managed metadata");
            }
            canonical.append(name).append('=').append(value).append('\n');
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.clone(), "HmacSHA256"));
            byte[] digest = mac.doFinal(canonical.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(64);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >>> 4) & 0xf, 16));
                hex.append(Character.forDigit(b & 0xf, 16));
            }
            return hex.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
