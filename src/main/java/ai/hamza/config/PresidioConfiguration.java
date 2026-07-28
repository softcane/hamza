package ai.hamza.config;

import ai.hamza.presidio.PresidioClient;
import ai.hamza.presidio.PresidioDetector;
import ai.hamza.presidio.PresidioProfile;
import java.net.URI;
import java.nio.file.Path;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the in-boundary Presidio detector only when an operator enables it. The
 * approved profile is loaded once at startup so an entity M3 disabled can never
 * enforce, and a broken profile fails startup instead of silently degrading.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(PresidioProperties.class)
@ConditionalOnProperty(prefix = "hamza.presidio", name = "enabled", havingValue = "true")
public class PresidioConfiguration {

    @Bean
    PresidioProfile presidioProfile(PresidioProperties properties) {
        return PresidioProfile.load(Path.of(properties.approvedProfile()));
    }

    @Bean
    PresidioClient presidioClient(PresidioProperties properties) {
        return new PresidioClient(URI.create(properties.endpoint()));
    }

    @Bean
    PresidioDetector presidioDetector(PresidioClient client, PresidioProfile profile) {
        return new PresidioDetector(client, profile);
    }
}
