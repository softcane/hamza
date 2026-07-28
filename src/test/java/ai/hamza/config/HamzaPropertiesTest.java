package ai.hamza.config;

import ai.hamza.policy.Action;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

class HamzaPropertiesTest {

    @Test
    void bindsPolicyPostureAndOversizeTunables() {
        MockEnvironment env = new MockEnvironment()
                .withProperty("hamza.policy.posture", "MASK")
                .withProperty("hamza.policy.max-body-bytes", "12345")
                .withProperty("hamza.policy.control-plane-paths[0]", "/large/control");

        HamzaProperties props = Binder.get(env)
                .bind("hamza", Bindable.of(HamzaProperties.class))
                .get();

        assertThat(props.policy().posture()).isEqualTo(Action.MASK);
        assertThat(props.policy().maxBodyBytes()).isEqualTo(12_345);
        assertThat(props.policy().controlPlanePaths()).containsExactly("/large/control");
    }

    @Test
    void bindsEdmIngestionTunables() {
        MockEnvironment env = new MockEnvironment()
                .withProperty("hamza.edm.registry-dir", "/data/edm-registries")
                .withProperty("hamza.edm.block-threshold", "12")
                .withProperty("hamza.edm.keep-previous", "false")
                .withProperty("hamza.edm.admin-token", "admin-token");

        HamzaProperties props = Binder.get(env)
                .bind("hamza", Bindable.of(HamzaProperties.class))
                .get();

        assertThat(props.edm().registryDir()).isEqualTo("/data/edm-registries");
        assertThat(props.edm().blockThreshold()).isEqualTo(12);
        assertThat(props.edm().keepPrevious()).isFalse();
        assertThat(props.edm().adminToken()).isEqualTo("admin-token");
        assertThat(props.edm().adminEnabled()).isTrue();
    }
}
