package ai.hamza.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * In-boundary Presidio Analyzer wiring. Disabled by default: a Gate only registers
 * the detector once an operator points it at the pinned in-boundary service and the
 * approved profile M3 produced.
 *
 * @param enabled           whether Presidio is a registered detector for managed Turns
 * @param endpoint          base URI of the in-boundary Analyzer; never a public host
 * @param approvedProfile   path to the M3 approved profile
 */
@ConfigurationProperties(prefix = "hamza.presidio")
@Validated
public record PresidioProperties(boolean enabled, @NotBlank String endpoint,
                                 @NotBlank String approvedProfile) {

    public static final String DEFAULT_ENDPOINT = "http://presidio:3000";
    public static final String DEFAULT_APPROVED_PROFILE =
            "/opt/hamza/presidio/approved-profile.json";

    @org.springframework.boot.context.properties.bind.ConstructorBinding
    public PresidioProperties {
        endpoint = endpoint == null || endpoint.isBlank() ? DEFAULT_ENDPOINT : endpoint;
        approvedProfile = approvedProfile == null || approvedProfile.isBlank()
                ? DEFAULT_APPROVED_PROFILE : approvedProfile;
    }
}
