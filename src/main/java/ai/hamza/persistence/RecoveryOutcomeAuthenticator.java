package ai.hamza.persistence;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/** HMAC authentication for append-only, content-free Recovery Outcome evidence. */
public final class RecoveryOutcomeAuthenticator {

    public static final String SIGNATURE_VERSION = "hamza-recovery-outcome-signature/v1";

    private final byte[] key;

    public RecoveryOutcomeAuthenticator(byte[] key) {
        if (key == null || key.length < 32) {
            throw new IllegalArgumentException("recovery outcome signing key is too short");
        }
        this.key = key.clone();
    }

    public RecoveryOutcome sign(RecoveryOutcome.Unsigned evidence) {
        return new RecoveryOutcome(evidence, SIGNATURE_VERSION, signature(evidence));
    }

    public boolean verify(RecoveryOutcome outcome) {
        if (outcome == null || !SIGNATURE_VERSION.equals(outcome.signatureVersion())) {
            return false;
        }
        byte[] expected = signature(outcome.evidence()).getBytes(StandardCharsets.US_ASCII);
        byte[] supplied = outcome.signature().getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(expected, supplied);
    }

    private String signature(RecoveryOutcome.Unsigned evidence) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key.clone(), "HmacSHA256"));
            byte[] digest = mac.doFinal(canonical(evidence).getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(64);
            for (byte value : digest) {
                hex.append(Character.forDigit((value >>> 4) & 0xf, 16));
                hex.append(Character.forDigit(value & 0xf, 16));
            }
            return hex.toString();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    private static String canonical(RecoveryOutcome.Unsigned evidence) {
        StringBuilder canonical = new StringBuilder(SIGNATURE_VERSION).append('\n');
        field(canonical, evidence.recoveryId());
        field(canonical, evidence.status().wireValue());
        field(canonical, evidence.agent());
        field(canonical, evidence.agentVersion());
        field(canonical, evidence.workflowProfileId());
        field(canonical, Integer.toString(evidence.workflowProfileVersion()));
        field(canonical, evidence.acceptanceGateId());
        field(canonical, evidence.startedAt().toString());
        field(canonical, evidence.completedAt().toString());
        return canonical.toString();
    }

    private static void field(StringBuilder canonical, String value) {
        byte[] utf8 = value.getBytes(StandardCharsets.UTF_8);
        canonical.append(utf8.length).append(':').append(value).append('\n');
    }
}
