package ai.hamza.adapter;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The operator-facing Adapter registry. It deliberately contains only content-free
 * Provider metadata and stateless Adapter instances so attestation CLIs can run without
 * a Spring context while contract tests can compare it to the live Adapter beans.
 */
public final class AdapterRegistry {

    private AdapterRegistry() {
    }

    public static List<ProviderAdapter> defaultAdapters() {
        return List.of(new OpenAiResponsesAdapter(), new AnthropicMessagesAdapter());
    }

    public static List<ProviderSpec> defaultSpecs() {
        return defaultAdapters().stream().map(ProviderAdapter::spec)
                .sorted(java.util.Comparator.comparing(ProviderSpec::provider))
                .toList();
    }

    public static Set<String> providerDomains() {
        Set<String> domains = new TreeSet<>();
        defaultSpecs().forEach(spec -> domains.addAll(spec.domains()));
        return domains;
    }

    public static DriftReport drift(Collection<ProviderAdapter> liveAdapters) {
        Map<String, ProviderSpec> registry = byProvider(defaultSpecs());
        Map<String, ProviderSpec> live = byProvider(liveAdapters == null ? List.of()
                : liveAdapters.stream().map(ProviderAdapter::spec).toList());
        Set<String> missingFromRegistry = new TreeSet<>(live.keySet());
        missingFromRegistry.removeAll(registry.keySet());
        Set<String> staleInRegistry = new TreeSet<>(registry.keySet());
        staleInRegistry.removeAll(live.keySet());
        Set<String> metadataMismatches = new TreeSet<>();
        for (String provider : live.keySet()) {
            if (registry.containsKey(provider) && !registry.get(provider).equals(live.get(provider))) {
                metadataMismatches.add(provider);
            }
        }
        return new DriftReport(missingFromRegistry, staleInRegistry, metadataMismatches);
    }

    private static Map<String, ProviderSpec> byProvider(Collection<ProviderSpec> specs) {
        Map<String, ProviderSpec> out = new TreeMap<>();
        for (ProviderSpec spec : specs) {
            out.put(spec.provider(), spec);
        }
        return out;
    }

    public record DriftReport(Set<String> missingFromRegistry, Set<String> staleInRegistry,
                              Set<String> metadataMismatches) {
        public boolean ok() {
            return missingFromRegistry.isEmpty()
                    && staleInRegistry.isEmpty()
                    && metadataMismatches.isEmpty();
        }
    }
}
