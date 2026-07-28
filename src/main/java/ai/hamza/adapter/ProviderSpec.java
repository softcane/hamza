package ai.hamza.adapter;

import java.util.List;

/**
 * Content-free Provider metadata owned by an Adapter: Provider name, sanctioned
 * egress domains, and Provider API paths. This is the single source for policy
 * artifact compilation and coverage watch-list reconciliation.
 */
public record ProviderSpec(String provider, List<String> domains, List<String> paths) {

    public ProviderSpec {
        domains = domains == null ? List.of() : domains.stream()
                .filter(s -> s != null && !s.isBlank())
                .map(String::toLowerCase)
                .sorted()
                .toList();
        paths = paths == null ? List.of() : paths.stream()
                .filter(s -> s != null && !s.isBlank())
                .sorted()
                .toList();
    }
}
