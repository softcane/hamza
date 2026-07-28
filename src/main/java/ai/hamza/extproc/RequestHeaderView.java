package ai.hamza.extproc;

import io.envoyproxy.envoy.config.core.v3.HeaderValue;
import io.envoyproxy.envoy.service.ext_proc.v3.HttpHeaders;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.LinkedHashSet;

/**
 * The only request-header projection retained by the Gate. Provider Authorization is
 * discarded while iterating and never enters either map.
 */
final class RequestHeaderView {

    static final String ROUTE_PROVIDER_HEADER = "x-hamza-route-provider";
    private static final Set<String> ROUTING_HEADER_NAMES = Set.of(
            ":path", "content-encoding", "content-length", "transfer-encoding",
            "user-agent", "session_id", "x-session-id", "conversation_id",
            "x-request-id");

    private final Map<String, String> routingHeaders;
    private final Map<String, List<String>> managedHeaders;
    private final Set<String> duplicateRoutingHeaders;
    private final List<String> routeProviderValues;

    private RequestHeaderView(Map<String, String> routingHeaders,
                              Map<String, List<String>> managedHeaders,
                              Set<String> duplicateRoutingHeaders,
                              List<String> routeProviderValues) {
        this.routingHeaders = Map.copyOf(routingHeaders);
        Map<String, List<String>> copied = new LinkedHashMap<>();
        managedHeaders.forEach((name, values) -> copied.put(name, List.copyOf(values)));
        this.managedHeaders = Map.copyOf(copied);
        this.duplicateRoutingHeaders = Set.copyOf(duplicateRoutingHeaders);
        this.routeProviderValues = List.copyOf(routeProviderValues);
    }

    static RequestHeaderView from(HttpHeaders headers) {
        Map<String, String> routing = new LinkedHashMap<>();
        Map<String, List<String>> managed = new LinkedHashMap<>();
        Set<String> duplicates = new LinkedHashSet<>();
        List<String> routeProviders = new ArrayList<>();
        for (HeaderValue header : headers.getHeaders().getHeadersList()) {
            String name = header.getKey().toLowerCase(Locale.ROOT);
            boolean internal = name.startsWith("x-hamza-");
            // Read values only for the fixed projection the Gate actually needs.
            // Provider auth may arrive in Authorization, x-api-key, Cookie, or a
            // future Provider-specific header; a denylist would inevitably copy one.
            if (!internal && !ROUTING_HEADER_NAMES.contains(name)) {
                continue;
            }
            String value = header.getValue();
            if (value == null || value.isEmpty()) {
                value = header.getRawValue().toStringUtf8();
            }
            if (name.equals(ROUTE_PROVIDER_HEADER)) {
                // Envoy removes any client value, writes the configured Provider, and
                // removes it again after ext_proc. Keep this routing hint separate from
                // signed managed metadata so it cannot alter the verified tuple.
                routeProviders.add(value);
            } else if (internal) {
                managed.computeIfAbsent(name, ignored -> new ArrayList<>()).add(value);
            } else {
                if (routing.put(name, value) != null) {
                    duplicates.add(name);
                }
            }
        }
        return new RequestHeaderView(routing, managed, duplicates, routeProviders);
    }

    Map<String, String> routingHeaders() {
        return routingHeaders;
    }

    Map<String, List<String>> managedHeaders() {
        return managedHeaders;
    }

    boolean duplicated(String headerName) {
        return duplicateRoutingHeaders.contains(headerName.toLowerCase(Locale.ROOT));
    }

    Set<String> duplicateRoutingHeaders() {
        return duplicateRoutingHeaders;
    }

    String routeProvider() {
        return routeProviderValues.size() == 1 ? routeProviderValues.getFirst() : null;
    }

    @Override
    public String toString() {
        int managedValues = managedHeaders.values().stream().mapToInt(List::size).sum();
        return "RequestHeaderView[routing=" + routingHeaders.size()
                + ", managed=" + managedValues
                + ", routeProvider=" + (routeProviderValues.size() == 1) + "]";
    }
}
