package ai.hamza.edm;

import ai.hamza.adapter.ContentSegment;
import ai.hamza.config.HamzaProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exact Data Match scanning with explicit complete-or-exhausted results. */
@Component
public class EdmMatcher {

    private static final Pattern TOKEN = Pattern.compile("[\\p{L}\\p{N}@._+\\-]+");
    private static final Pattern EMAIL = Pattern.compile(
            "[\\p{L}\\p{N}.!#$%&'*+/=?^_`{|}~-]+@[\\p{L}\\p{N}]"
                    + "(?:[\\p{L}\\p{N}-]{0,61}[\\p{L}\\p{N}])?"
                    + "(?:\\.[\\p{L}\\p{N}]"
                    + "(?:[\\p{L}\\p{N}-]{0,61}[\\p{L}\\p{N}])?)+");
    private static final Pattern CONTINUATION_CANDIDATE = Pattern.compile("\\S+");
    private static final Pattern DIGIT_TOKEN = Pattern.compile("[0-9+\\-.]+");
    private static final int MAX_DIGIT_RUN = 6;
    static final int DEFAULT_MAX_CANDIDATES = 50_000;
    private static final int MAX_CANDIDATE_CHARS = 512;
    private static final String EMAIL_EMBEDDING_DELIMITERS = "='`{|}/";

    private final RegistryStore store;
    private final List<FingerprintRegistry> fixedLegacy;
    private final List<TypedRegistry> fixedTyped;
    private final int maxCandidates;

    @Autowired
    public EdmMatcher(RegistryStore store, HamzaProperties properties) {
        this.store = store;
        this.fixedLegacy = null;
        this.fixedTyped = null;
        this.maxCandidates = properties.continuation().candidateBudget();
    }

    public EdmMatcher(RegistryStore store) {
        this.store = store;
        this.fixedLegacy = null;
        this.fixedTyped = null;
        this.maxCandidates = DEFAULT_MAX_CANDIDATES;
    }

    /** Explicit immutable Registry snapshot, used by isolated module tests and tooling. */
    public EdmMatcher(List<FingerprintRegistry> legacy, List<TypedRegistry> typed,
                      int maxCandidates) {
        this.store = null;
        this.fixedLegacy = List.copyOf(legacy);
        this.fixedTyped = List.copyOf(typed);
        if (maxCandidates <= 0) {
            throw new IllegalArgumentException("candidate budget must be positive");
        }
        this.maxCandidates = maxCandidates;
    }

    public boolean enabled() {
        return !legacyRegistries().isEmpty() || !typedRegistries().isEmpty();
    }

    /** Compatibility projection. Exhaustion is never converted into a clean result. */
    public Map<String, Integer> match(String text) {
        EdmCountScanResult result = scanCounts(text);
        requireComplete(result);
        return result.counts();
    }

    /** Scan policy text across v1 and v2 Registries with an explicit completeness signal. */
    public EdmCountScanResult scanCounts(String text) {
        Map<String, Set<Long>> legacy = new HashMap<>();
        Map<String, Set<FullFingerprint>> typed = new HashMap<>();
        Budget budget = new Budget(maxCandidates);
        if (text == null || text.isEmpty() || !enabled()) {
            return new EdmCountScanResult(legacy, typed, null, 0);
        }

        List<FingerprintRegistry> legacyRegistries = legacyRegistries();
        List<TypedRegistry> typedRegistries = typedRegistries();
        boolean complete = scanLegacyCandidates(
                text, legacyRegistries, legacy, budget);
        if (complete) {
            complete = scanTypedEmailCandidates(
                    text, typedRegistries, typed, budget);
        }
        return new EdmCountScanResult(legacy, typed,
                complete ? null : EdmScanExhaustionReason.CANDIDATE_LIMIT, budget.used);
    }

    private boolean scanLegacyCandidates(String text,
                                         List<FingerprintRegistry> registries,
                                         Map<String, Set<Long>> matches,
                                         Budget budget) {
        if (registries.isEmpty()) {
            return true;
        }
        Matcher matcher = TOKEN.matcher(text);
        Candidate previous = null;
        List<Candidate> digitRun = new ArrayList<>(MAX_DIGIT_RUN);
        boolean complete = true;
        outer:
        while (matcher.find()) {
            Candidate token = trimmedToken(text, matcher.start(), matcher.end());
            if (!checkLegacyCandidate(text, token, registries, matches, budget)) {
                complete = false;
                if (budget.exhausted()) {
                    return false;
                }
            }
            Candidate pair = previous == null ? null
                    : new Candidate(previous.start(), token.end());
            // A two-token value cannot exceed the enforced candidate bound. A large
            // whitespace/punctuation gap between otherwise bounded tokens is therefore
            // not an uninspected candidate and must not poison scan completeness.
            if (pair != null && pair.end() - pair.start() <= MAX_CANDIDATE_CHARS
                    && !checkLegacyCandidate(text, pair, registries, matches, budget)) {
                complete = false;
                if (budget.exhausted()) {
                    return false;
                }
            }
            if (!DIGIT_TOKEN.matcher(token.value(text)).matches()) {
                digitRun.clear();
            } else {
                digitRun.add(token);
                if (digitRun.size() > MAX_DIGIT_RUN) {
                    digitRun.removeFirst();
                }
                for (int n = 3; n <= digitRun.size(); n++) {
                    Candidate run = new Candidate(digitRun.get(digitRun.size() - n).start(), token.end());
                    if (!checkLegacyCandidate(text, run, registries, matches, budget)) {
                        complete = false;
                        break outer;
                    }
                }
            }
            previous = token;
        }
        return complete;
    }

    private boolean scanTypedEmailCandidates(String text,
                                             List<TypedRegistry> registries,
                                             Map<String, Set<FullFingerprint>> matches,
                                             Budget budget) {
        if (registries.isEmpty()) {
            return true;
        }
        Matcher emails = EMAIL.matcher(text);
        while (emails.find()) {
            String raw = emails.group();
            if (raw.length() > MAX_CANDIDATE_CHARS) {
                return false;
            }
            for (EmailCandidate candidate : emailCandidates(emails)) {
                if (!budget.claim()) {
                    return false;
                }
                String normalized = Fingerprinter.normalize(candidate.value());
                if (!Fingerprinter.strongEnough(normalized)) {
                    continue;
                }
                for (TypedRegistry registry : registries) {
                    FullFingerprint fingerprint = Fingerprinter.fullFingerprint(
                            registry.salt(), normalized);
                    if (registry.fields().values().stream()
                            .anyMatch(field -> field.kind() == ReplacementKind.EMAIL
                                    && field.fingerprints().contains(fingerprint))) {
                        matches.computeIfAbsent(registry.id(), ignored -> new HashSet<>())
                                .add(fingerprint);
                    }
                }
            }
        }
        return true;
    }

    /** Locate every typed EMAIL occurrence inside approved decoded Adapter segments. */
    public EdmScanResult scanContinuation(List<ContentSegment> segments) {
        List<EdmMatch> matches = new ArrayList<>();
        Map<String, Set<FullFingerprint>> distinct = new LinkedHashMap<>();
        Budget budget = new Budget(maxCandidates);
        boolean complete = true;
        if (segments == null) {
            segments = List.of();
        }
        outer:
        for (ContentSegment segment : segments) {
            Matcher candidates = CONTINUATION_CANDIDATE.matcher(segment.text());
            while (candidates.find()) {
                if (!budget.claim()) {
                    complete = false;
                    break outer;
                }
                if (candidates.end() - candidates.start() > MAX_CANDIDATE_CHARS) {
                    complete = false;
                    if (budget.exhausted()) {
                        break outer;
                    }
                    continue;
                }
                Matcher emails = EMAIL.matcher(candidates.group());
                while (emails.find()) {
                    for (EmailCandidate candidate : emailCandidates(emails)) {
                        String normalized = Fingerprinter.normalize(candidate.value());
                        if (!Fingerprinter.strongEnough(normalized)) {
                            continue;
                        }
                        int start = candidates.start() + candidate.start();
                        int end = candidates.start() + candidate.end();
                        for (TypedRegistry registry : typedRegistries()) {
                            FullFingerprint fingerprint = Fingerprinter.fullFingerprint(
                                    registry.salt(), normalized);
                            for (TypedRegistry.Field field : registry.fields().values()) {
                                if (field.kind() == ReplacementKind.EMAIL
                                        && field.fingerprints().contains(fingerprint)) {
                                    matches.add(new EdmMatch(registry.id(), field.id(), field.kind(),
                                            fingerprint, segment.id(), start, end));
                                    distinct.computeIfAbsent(registry.id(), ignored -> new HashSet<>())
                                            .add(fingerprint);
                                }
                            }
                        }
                    }
                }
            }
        }
        Map<String, Integer> counts = new LinkedHashMap<>();
        distinct.forEach((registry, fingerprints) -> counts.put(registry, fingerprints.size()));
        return new EdmScanResult(matches, counts,
                complete ? null : EdmScanExhaustionReason.CANDIDATE_LIMIT, budget.used);
    }

    public int blockThreshold(String registryId, int legacyFallback) {
        return typedRegistries().stream()
                .filter(registry -> registry.id().equals(registryId))
                .mapToInt(TypedRegistry::blockThreshold)
                .min()
                .orElse(legacyFallback);
    }

    public List<TypedRegistry> typedRegistries() {
        return store == null ? fixedTyped : store.typedRegistries();
    }

    private List<FingerprintRegistry> legacyRegistries() {
        return store == null ? fixedLegacy : store.registries();
    }

    private boolean checkLegacyCandidate(String text, Candidate candidate,
                                         List<FingerprintRegistry> registries,
                                         Map<String, Set<Long>> matches,
                                         Budget budget) {
        String raw = candidate.value(text);
        String normalized = Fingerprinter.normalize(raw);
        if (!Fingerprinter.strongEnough(normalized)) {
            return true;
        }
        if (!budget.claim()) {
            return false;
        }
        if (raw.length() > MAX_CANDIDATE_CHARS) {
            return false;
        }
        for (FingerprintRegistry registry : registries) {
            long fingerprint = Fingerprinter.fingerprint(registry.salt(), normalized);
            if (registry.fingerprints().contains(fingerprint)) {
                matches.computeIfAbsent(registry.name(), ignored -> new HashSet<>()).add(fingerprint);
            }
        }
        return true;
    }

    /**
     * The RFC-style local-part pattern permits several characters that also delimit
     * embedded values. Structured text such as {@code owner=user@example.test} or
     * a shell-quoted address therefore has one maximal regex match even though the
     * Registry value starts later. Check suffixes after that small delimiter set as
     * well as the full valid address; exact fingerprints keep the expansion
     * false-positive safe.
     */
    private static List<EmailCandidate> emailCandidates(Matcher matcher) {
        String raw = matcher.group();
        List<EmailCandidate> candidates = new ArrayList<>();
        candidates.add(new EmailCandidate(raw, matcher.start(), matcher.end()));
        for (int i = raw.length() - 1; i >= 0; i--) {
            if (EMAIL_EMBEDDING_DELIMITERS.indexOf(raw.charAt(i)) < 0
                    || i + 1 >= raw.length()) {
                continue;
            }
            String suffix = raw.substring(i + 1);
            if (EMAIL.matcher(suffix).matches()) {
                candidates.add(new EmailCandidate(
                        suffix, matcher.start() + i + 1, matcher.end()));
            }
        }
        return candidates;
    }

    private static Candidate trimmedToken(String text, int start, int end) {
        while (end > start && text.charAt(end - 1) == '.') {
            end--;
        }
        return new Candidate(start, end);
    }

    private static void requireComplete(EdmCountScanResult result) {
        if (!result.complete()) {
            throw new IllegalStateException("edm-scan-exhausted");
        }
    }

    static Map<String, Integer> counts(Map<String, ? extends Set<?>> distinct) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        distinct.forEach((registry, fingerprints) -> counts.put(registry, fingerprints.size()));
        return Map.copyOf(counts);
    }

    private record Candidate(int start, int end) {
        String value(String text) {
            return text.substring(start, end);
        }
    }

    private record EmailCandidate(String value, int start, int end) {
    }

    private static final class Budget {
        private final int maximum;
        private int used;

        private Budget(int maximum) {
            this.maximum = maximum;
        }

        private boolean claim() {
            if (used >= maximum) {
                return false;
            }
            used++;
            return true;
        }

        private boolean exhausted() {
            return used >= maximum;
        }
    }
}
