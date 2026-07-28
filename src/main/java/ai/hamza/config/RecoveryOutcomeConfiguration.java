package ai.hamza.config;

import ai.hamza.persistence.RecoveryOutcomeAuthenticator;
import ai.hamza.persistence.RecoveryOutcomeRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.Clock;

/** Production JDBC wiring for signed terminal evidence, separate from domain tests. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "hamza.continuation", name = "enabled", havingValue = "true")
public class RecoveryOutcomeConfiguration {

    @Bean
    RecoveryOutcomeAuthenticator recoveryOutcomeAuthenticator(HamzaProperties properties) {
        return new RecoveryOutcomeAuthenticator(properties.continuation().managed()
                .decodedSigningKey().orElseThrow());
    }

    @Bean
    RecoveryOutcomeRepository recoveryOutcomeRepository(
            JdbcClient jdbc,
            RecoveryOutcomeAuthenticator authenticator,
            Clock continuationClock,
            PlatformTransactionManager transactionManager) {
        return new RecoveryOutcomeRepository(jdbc, authenticator, continuationClock,
                transactionManager);
    }
}
