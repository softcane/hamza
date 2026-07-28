package ai.hamza.edm;

import ai.hamza.adapter.ContentSegment;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class EdmContinuationScanTest {

    private static final byte[] SALT = "01234567890123456789012345678901"
            .getBytes(StandardCharsets.UTF_8);
    private static final String EMAIL = "priya.fixture@example-corp.test";
    private static final String UTF8_EMAIL = "café.fixture@example-corp.test";

    @Test
    void locatesEveryDecodedEmailOccurrenceWithFullTypedIdentity() {
        EdmMatcher matcher = matcher(100, field("email", ReplacementKind.EMAIL, EMAIL));
        List<ContentSegment> segments = List.of(
                new ContentSegment("segment-0", "Review \"café\" for " + EMAIL + "."),
                new ContentSegment("segment-1", EMAIL + " then " + EMAIL));

        EdmScanResult result = matcher.scanContinuation(segments);

        assertThat(result.complete()).isTrue();
        assertThat(result.matches()).hasSize(3).allSatisfy(match -> {
            assertThat(match.registryId()).isEqualTo("customers");
            assertThat(match.fieldId()).isEqualTo("email");
            assertThat(match.kind()).isEqualTo(ReplacementKind.EMAIL);
            assertThat(match.fingerprint()).isEqualTo(Fingerprinter.fullFingerprint(SALT, EMAIL));
            ContentSegment segment = segments.stream()
                    .filter(item -> item.id().equals(match.contentSegmentId()))
                    .findFirst().orElseThrow();
            assertThat(segment.text().substring(match.start(), match.end())).isEqualTo(EMAIL);
        });
        assertThat(result.distinctCounts()).containsEntry("customers", 1);
        assertThat(result.toString()).doesNotContain(EMAIL, "email",
                Fingerprinter.fullFingerprint(SALT, EMAIL).toHex());
    }

    @Test
    void aCandidateAfterTheWorkLimitMakesTheScanExhaustedNotClean() {
        EdmMatcher matcher = matcher(3, field("email", ReplacementKind.EMAIL, EMAIL));
        ContentSegment segment = new ContentSegment("segment-0",
                "alpha000 beta000 gamma000 " + EMAIL);

        EdmScanResult result = matcher.scanContinuation(List.of(segment));

        assertThat(result.complete()).isFalse();
        assertThat(result.exhaustionReason()).contains(EdmScanExhaustionReason.CANDIDATE_LIMIT);
        assertThat(result.matches()).isEmpty();
        assertThat(result.candidatesExamined()).isEqualTo(3);
    }

    @Test
    void oneFingerprintInTwoFieldsRemainsAmbiguousForEligibility() {
        FullFingerprint fingerprint = Fingerprinter.fullFingerprint(SALT, EMAIL);
        TypedRegistry registry = TypedRegistry.create("customers", SALT, 1,
                new RegistryRecipe("synthetic-email", 1), Map.of(
                        "email", new TypedRegistry.Field("email", ReplacementKind.EMAIL,
                                Set.of(fingerprint)),
                        "backup_email", new TypedRegistry.Field("backup_email", ReplacementKind.EMAIL,
                                Set.of(fingerprint))));
        EdmMatcher matcher = new EdmMatcher(List.of(), List.of(registry), 100);

        EdmScanResult result = matcher.scanContinuation(List.of(
                new ContentSegment("segment-0", EMAIL)));

        assertThat(result.matches()).hasSize(2);
        assertThat(result.matches()).extracting(EdmMatch::fieldId)
                .containsExactlyInAnyOrder("email", "backup_email");
    }

    @Test
    void countScanAlsoReportsExhaustionAndUsesTypedThreshold() {
        EdmMatcher matcher = matcher(3, field("email", ReplacementKind.EMAIL, EMAIL));

        EdmCountScanResult result = matcher.scanCounts(
                "one@example.test two@example.test three@example.test " + EMAIL);

        assertThat(result.complete()).isFalse();
        assertThat(result.exhaustionReason()).contains(EdmScanExhaustionReason.CANDIDATE_LIMIT);
        assertThat(matcher.blockThreshold("customers", 10)).isEqualTo(1);
    }

    @Test
    void typedEmailScanDoesNotSpendBudgetOnIrrelevantWireTokens() {
        EdmMatcher matcher = matcher(1, field("email", ReplacementKind.EMAIL, EMAIL));
        String irrelevantWireContext = "alpha000 beta000 gamma000 ".repeat(30_000);

        EdmCountScanResult result = matcher.scanCounts(irrelevantWireContext + EMAIL);

        assertThat(result.complete()).isTrue();
        assertThat(result.candidatesExamined()).isEqualTo(1);
        assertThat(result.counts()).containsEntry("customers", 1);
    }

    @Test
    void locatesAndCountsUtf8EmailWithoutByteOrCharacterOffsetDrift() {
        EdmMatcher matcher = matcher(100, field("email", ReplacementKind.EMAIL, UTF8_EMAIL));
        ContentSegment segment = new ContentSegment("segment-0",
                "prefix 😀 " + UTF8_EMAIL + " suffix");

        EdmScanResult located = matcher.scanContinuation(List.of(segment));
        EdmCountScanResult counted = matcher.scanCounts(segment.text());

        assertThat(located.complete()).isTrue();
        assertThat(located.matches()).singleElement().satisfies(match ->
                assertThat(segment.text().substring(match.start(), match.end()))
                        .isEqualTo(UTF8_EMAIL));
        assertThat(counted.complete()).isTrue();
        assertThat(counted.counts()).containsEntry("customers", 1);
    }

    @Test
    void assignmentPrefixIsNotIncludedInContinuationReplacementSpan() {
        EdmMatcher matcher = matcher(100, field("email", ReplacementKind.EMAIL, EMAIL));
        ContentSegment segment = new ContentSegment("segment-0", "owner=" + EMAIL + " amount=10");

        EdmScanResult result = matcher.scanContinuation(List.of(segment));

        assertThat(result.complete()).isTrue();
        assertThat(result.matches()).singleElement().satisfies(match ->
                assertThat(segment.text().substring(match.start(), match.end())).isEqualTo(EMAIL));
        assertThat(result.distinctCounts()).containsEntry("customers", 1);
    }

    @Test
    void equalsInsideRegisteredLocalPartStillMatchesTheFullEmail() {
        String emailWithEquals = "ops=team@example-corp.test";
        EdmMatcher matcher = matcher(100,
                field("email", ReplacementKind.EMAIL, emailWithEquals));
        ContentSegment segment = new ContentSegment("segment-0", emailWithEquals);

        EdmScanResult result = matcher.scanContinuation(List.of(segment));

        assertThat(result.complete()).isTrue();
        assertThat(result.matches()).singleElement().satisfies(match ->
                assertThat(segment.text().substring(match.start(), match.end()))
                        .isEqualTo(emailWithEquals));
    }

    @Test
    void quotePrefixIsNotIncludedInContinuationReplacementSpan() {
        EdmMatcher matcher = matcher(100, field("email", ReplacementKind.EMAIL, EMAIL));
        ContentSegment segment = new ContentSegment("segment-0", "lookup '" + EMAIL + "'");

        EdmScanResult result = matcher.scanContinuation(List.of(segment));

        assertThat(result.complete()).isTrue();
        assertThat(result.matches()).singleElement().satisfies(match ->
                assertThat(segment.text().substring(match.start(), match.end())).isEqualTo(EMAIL));
    }

    private static EdmMatcher matcher(int budget, TypedRegistry.Field field) {
        TypedRegistry registry = TypedRegistry.create("customers", SALT, 1,
                new RegistryRecipe("synthetic-email", 1), Map.of(field.id(), field));
        return new EdmMatcher(List.of(), List.of(registry), budget);
    }

    private static TypedRegistry.Field field(String id, ReplacementKind kind, String value) {
        return new TypedRegistry.Field(id, kind,
                Set.of(Fingerprinter.fullFingerprint(SALT, Fingerprinter.normalize(value))));
    }
}
