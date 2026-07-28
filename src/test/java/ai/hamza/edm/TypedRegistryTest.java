package ai.hamza.edm;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class TypedRegistryTest {

    private static final FullFingerprint FP = FullFingerprint.parseHex("11".repeat(32));

    @Test
    void canonicalVersionCoversEveryTypedRegistryField() {
        byte[] salt = "01234567890123456789012345678901".getBytes();
        RegistryRecipe recipe = new RegistryRecipe("synthetic-email", 1);
        Map<String, TypedRegistry.Field> fields = Map.of(
                "email", new TypedRegistry.Field("email", ReplacementKind.EMAIL, Set.of(FP)));

        TypedRegistry registry = TypedRegistry.create("customers", salt, 1, recipe, fields);

        assertThat(registry.version())
                .isEqualTo("a4b31799c3b3b3afd88f9c5e0eda9af9cb4b1405f5a17300d5fbedb8a1fc6764");
        assertThat(TypedRegistry.create("prospects", salt, 1, recipe, fields).version())
                .isNotEqualTo(registry.version());
        assertThat(TypedRegistry.create("customers", salt, 2, recipe, fields).version())
                .isNotEqualTo(registry.version());
    }

    @Test
    void registryAndFieldsAreImmutableAndBounded() {
        byte[] salt = new byte[32];
        TypedRegistry registry = TypedRegistry.create("customers", salt, 1,
                new RegistryRecipe("synthetic-email", 1),
                Map.of("email", new TypedRegistry.Field(
                        "email", ReplacementKind.EMAIL, Set.of(FP))));
        salt[0] = 1;
        byte[] exposedSalt = registry.salt();
        exposedSalt[1] = 2;

        assertThat(registry.salt()).containsOnly(0);
        assertThatIllegalArgumentException().isThrownBy(() -> new TypedRegistry.Field(
                "not a field", ReplacementKind.EMAIL, Set.of(FP)));
        assertThatIllegalArgumentException().isThrownBy(() -> TypedRegistry.create(
                "customers", new byte[31], 1, new RegistryRecipe("synthetic-email", 1),
                registry.fields()));
    }

    @Test
    void loaderRejectsADeclaredVersionThatDoesNotMatchCanonicalContent() {
        assertThatIllegalArgumentException().isThrownBy(() -> TypedRegistry.load(
                "customers", "00".repeat(32), new byte[32], 1,
                new RegistryRecipe("synthetic-email", 1),
                Map.of("email", new TypedRegistry.Field(
                        "email", ReplacementKind.EMAIL, Set.of(FP)))));
    }
}
