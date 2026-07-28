package ai.hamza;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Boots the REAL application context. Exists because "compiles and unit tests pass but
 * the app cannot start" is otherwise invisible to {@code mvn verify} — exactly what
 * happened when RegistryStore gained a second constructor without {@code @Autowired}
 * (2026-07-06): every test was green while the container exited(1) at startup.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite:${java.io.tmpdir}/hamza-context-smoke-${random.uuid}.db",
        "spring.grpc.server.port=0",
        "server.port=0"
})
class HamzaApplicationSmokeTest {

    @Test
    void contextLoads() {
        // Passing means every bean (adapters, policy engine, EDM store, ext_proc
        // service, metrics, persistence) wired and the app would boot.
    }
}
