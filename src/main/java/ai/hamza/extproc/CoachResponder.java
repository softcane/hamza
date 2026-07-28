package ai.hamza.extproc;

import ai.hamza.config.HamzaProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * How Block speaks. Coach is <em>not</em> a fourth Action rung: it
 * only changes the <em>presentation</em> of a Block, never whether the Turn is blocked or
 * what blocked it. When enabled, a blocked Egress returns a Provider-shaped, model-legible
 * error body that names the matched <strong>rule class only</strong> (never the matched
 * content, never registry-row data), forbids retry/re-encoding, and proposes a compliant
 * path (synthetic data, ask the developer, the sanctioned channel).
 *
 * <p>Content-free invariant: the coach body is rendered solely from the block
 * status and the blocking rule-class names — the same content-free material the Record
 * already holds. No inspected bytes ever reach this class.
 *
 * <p>Disabled by default: a Gate with {@code hamza.coach.enabled=false} emits the bare
 * text 403 exactly as before (the R3.1 control arm / bare-403 fallback), so Coach is a
 * pure opt-in on top of an unchanged Block decision.
 */
@Component
public class CoachResponder {

    /** Bare-403 body, byte-for-byte the pre-Coach block reason (control arm / fallback). */
    static final String BARE_REASON_PREFIX = "Blocked by Hamza: ";

    private static final String DEFAULT_MESSAGE =
            "Your organization's egress gateway (Hamza) withheld this request before it "
                    + "reached the model Provider. Rule class: {rules}. This is a data-egress "
                    + "control, not a Provider error. Do NOT retry the same request and do NOT "
                    + "re-encode, chunk, or obfuscate the same content — a re-encoded retry in "
                    + "this session is blocked harder and flagged as evasion. Complete the task "
                    + "with synthetic or sample data, ask the developer for a masked copy, or "
                    + "use the sanctioned data channel.";

    private final ObjectMapper mapper = new ObjectMapper();
    private final boolean enabled;
    private final int status;
    private final Map<String, String> messageTemplates;

    @Autowired
    public CoachResponder(HamzaProperties properties) {
        this(properties.coach().enabled(), properties.coach().status(), properties.coach().templates());
    }

    CoachResponder(boolean enabled, int status, Map<String, String> messageTemplates) {
        this.enabled = enabled;
        this.status = status > 0 ? status : 403;
        this.messageTemplates = messageTemplates == null ? Map.of() : Map.copyOf(messageTemplates);
    }

    /** A Coach that is off: always the bare text 403. Used where no config is wired (tests). */
    static CoachResponder disabled() {
        return new CoachResponder(false, 403, Map.of());
    }

    boolean enabled() {
        return enabled;
    }

    /**
     * Build the immediate block response for a Turn. Coach never changes WHETHER a Turn is
     * blocked — the caller has already decided to Block — only how the 403 body reads.
     *
     * @param provider      authoritative Provider of the matched Adapter, or {@code null}
     *                      when no Adapter matched (then the bare text body is used)
     * @param blockingRules the content-free rule-class names that forced the Block
     */
    ProcessingResponse blockResponse(String provider, List<String> blockingRules) {
        List<String> rules = blockingRules == null || blockingRules.isEmpty()
                ? List.of(TurnState.OVERSIZE_RULE) : blockingRules;
        String ruleList = String.join(",", rules);
        if (!enabled || provider == null || provider.isBlank()) {
            return ProcessingResponses.block(403, BARE_REASON_PREFIX + ruleList + "\n");
        }
        return switch (provider) {
            case "openai" -> ProcessingResponses.block(status,
                    openAiBody(ruleList), "application/json");
            case "anthropic" -> ProcessingResponses.block(status,
                    anthropicBody(ruleList), "application/json");
            // An Adapter we do not have a wire shape for: never guess a foreign envelope,
            // fall back to the honest bare 403 so we never emit an invalid body.
            default -> ProcessingResponses.block(403, BARE_REASON_PREFIX + ruleList + "\n");
        };
    }

    private String message(String provider, String ruleList) {
        String template = messageTemplates.getOrDefault(provider,
                messageTemplates.getOrDefault("default", DEFAULT_MESSAGE));
        return template.replace("{rules}", ruleList);
    }

    /**
     * OpenAI error envelope ({@code /v1/responses}); Codex CLI surfaces {@code error.message}.
     * Shape: {@code {"error":{"type":..,"code":..,"message":..,"param":null}}}.
     */
    private byte[] openAiBody(String ruleList) {
        ObjectNode error = mapper.createObjectNode();
        error.put("type", "egress_withheld");
        error.put("code", "hamza_egress_withheld");
        error.put("message", message("openai", ruleList));
        error.putNull("param");
        ObjectNode root = mapper.createObjectNode();
        root.set("error", error);
        return toBytes(root, ruleList);
    }

    /**
     * Anthropic error envelope ({@code /v1/messages}); Claude Code surfaces the error type +
     * message. Shape: {@code {"type":"error","error":{"type":"permission_error","message":..}}}.
     */
    private byte[] anthropicBody(String ruleList) {
        ObjectNode error = mapper.createObjectNode();
        error.put("type", "permission_error");
        error.put("message", message("anthropic", ruleList));
        ObjectNode root = mapper.createObjectNode();
        root.put("type", "error");
        root.set("error", error);
        return toBytes(root, ruleList);
    }

    private byte[] toBytes(ObjectNode node, String ruleList) {
        try {
            return mapper.writeValueAsBytes(node);
        } catch (Exception e) {
            // Serialization of a tiny content-free node cannot realistically fail, but if it
            // did we must still Block — degrade to the bare text body, never leak or pass.
            return (BARE_REASON_PREFIX + ruleList + "\n").getBytes(StandardCharsets.UTF_8);
        }
    }
}
