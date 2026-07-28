package ai.hamza;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Hamza — the vendor-neutral Gate that every CLI coding Agent routes through on its
 * way to a model Provider. See CONTEXT.md for the ubiquitous language.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class HamzaApplication {

    public static void main(String[] args) {
        SpringApplication.run(HamzaApplication.class, args);
    }
}
