package ai.hamza.masking;

import ai.hamza.edm.EdmMatcher;
import ai.hamza.edm.Fingerprinter;
import ai.hamza.edm.RegistryRecipe;
import ai.hamza.edm.ReplacementKind;
import ai.hamza.edm.TypedRegistry;
import ai.hamza.policy.Action;
import ai.hamza.policy.Masker;
import ai.hamza.policy.PolicyEngine;
import ai.hamza.policy.SecretDetector;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class MaskingTestFixture {

    static final String EMAIL = "anna.fixture@example.invalid";
    static final String SECRET = "AKIAABCDEFGHIJKLMNOP";
    private static final byte[] SALT = "01234567890123456789012345678901"
            .getBytes(StandardCharsets.UTF_8);

    private MaskingTestFixture() {
    }

    static MaskContinuationService service() {
        EdmMatcher edm = matcher(50_000);
        SecretDetector secrets = new SecretDetector();
        PolicyEngine policy = new PolicyEngine(secrets, new Masker(), Action.MASK, Map.of(),
                edm, 1);
        MaskScopeStore scopes = new MaskScopeStore();
        return new MaskContinuationService(
                new MaskDetectionService(secrets, edm, policy),
                new MaskPlanner(scopes), scopes);
    }

    static EdmMatcher matcher(int candidateBudget) {
        var fingerprint = Fingerprinter.fullFingerprint(
                SALT, Fingerprinter.normalize(EMAIL));
        TypedRegistry registry = TypedRegistry.create("customers", SALT, 1,
                new RegistryRecipe("mask-email", 1),
                Map.of("email", new TypedRegistry.Field(
                        "email", ReplacementKind.EMAIL, Set.of(fingerprint))));
        return new EdmMatcher(List.of(), List.of(registry), candidateBudget);
    }
}
