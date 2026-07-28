package ai.hamza.attest;

import ai.hamza.adapter.AdapterRegistry;
import ai.hamza.adapter.ProviderSpec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Compiles content-free egress-policy artifacts from the Adapter registry:
 * Cilium FQDN policy YAML, a generic firewall object-group/domain list, and an
 * Envoy/proxy ACL fragment. Domains and paths only; never prompts, bodies, or secrets.
 */
public final class PolicyArtifactCompiler {

    private PolicyArtifactCompiler() {
    }

    public static void main(String[] args) throws IOException {
        Map<String, String> opts = parseArgs(args);
        Path outDir = Path.of(opts.getOrDefault("out-dir", "policy-artifacts"));
        Files.createDirectories(outDir);
        CompiledArtifacts compiled = compile(AdapterRegistry.defaultSpecs(), Instant.now().toString());
        Files.writeString(outDir.resolve("cilium-provider-egress.yaml"), compiled.ciliumYaml(),
                StandardCharsets.UTF_8);
        Files.writeString(outDir.resolve("firewall-provider-domains.txt"), compiled.firewallDomains(),
                StandardCharsets.UTF_8);
        Files.writeString(outDir.resolve("envoy-provider-acl.yaml"), compiled.envoyAclYaml(),
                StandardCharsets.UTF_8);
        System.out.printf("[policy-artifacts] providers=%d domains=%d wrote %s%n",
                compiled.providerCount(), compiled.domainCount(), outDir);
    }

    public static CompiledArtifacts compile(List<ProviderSpec> specs, String generatedAt) {
        List<ProviderSpec> ordered = specs.stream()
                .sorted(java.util.Comparator.comparing(ProviderSpec::provider))
                .toList();
        return new CompiledArtifacts(cilium(ordered, generatedAt),
                firewall(ordered, generatedAt), envoyAcl(ordered, generatedAt),
                ordered.size(), ordered.stream().mapToInt(s -> s.domains().size()).sum());
    }

    private static String cilium(List<ProviderSpec> specs, String generatedAt) {
        StringBuilder sb = header("cilium-fqdn-policy", generatedAt);
        sb.append("apiVersion: cilium.io/v2\n")
                .append("kind: CiliumNetworkPolicy\n")
                .append("metadata:\n")
                .append("  name: hamza-provider-egress\n")
                .append("spec:\n")
                .append("  endpointSelector: {}\n")
                .append("  egress:\n")
                .append("    - toFQDNs:\n");
        for (String domain : allDomains(specs)) {
            sb.append("        - matchName: ").append(domain).append('\n');
        }
        return sb.toString();
    }

    private static String firewall(List<ProviderSpec> specs, String generatedAt) {
        StringBuilder sb = header("firewall-domain-object-group", generatedAt);
        sb.append("# object-group: hamza-provider-domains\n");
        for (String domain : allDomains(specs)) {
            sb.append(domain).append('\n');
        }
        return sb.toString();
    }

    private static String envoyAcl(List<ProviderSpec> specs, String generatedAt) {
        StringBuilder sb = header("envoy-provider-acl", generatedAt);
        sb.append("provider_allowlist:\n");
        for (ProviderSpec spec : specs) {
            sb.append("  - provider: ").append(spec.provider()).append('\n');
            sb.append("    domains:\n");
            for (String domain : spec.domains()) {
                sb.append("      - ").append(domain).append('\n');
            }
            sb.append("    paths:\n");
            for (String path : spec.paths()) {
                sb.append("      - ").append(path).append('\n');
            }
        }
        return sb.toString();
    }

    private static List<String> allDomains(List<ProviderSpec> specs) {
        return specs.stream().flatMap(s -> s.domains().stream()).distinct().sorted().toList();
    }

    private static StringBuilder header(String artifact, String generatedAt) {
        return new StringBuilder()
                .append("# generated_by: hamza-policy-artifact-compiler\n")
                .append("# artifact: ").append(artifact).append('\n')
                .append("# generated_at: ").append(generatedAt).append('\n')
                .append("# content: provider domains and paths only\n");
    }

    private static Map<String, String> parseArgs(String[] args) {
        Map<String, String> opts = new LinkedHashMap<>();
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--") && i + 1 < args.length) {
                opts.put(a.substring(2), args[++i]);
            }
        }
        return opts;
    }

    public record CompiledArtifacts(String ciliumYaml, String firewallDomains,
                                    String envoyAclYaml, int providerCount,
                                    int domainCount) {
    }
}
