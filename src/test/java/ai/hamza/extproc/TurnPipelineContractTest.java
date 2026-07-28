package ai.hamza.extproc;

import ai.hamza.metrics.HamzaMetrics;
import ai.hamza.persistence.TurnRepository;
import ai.hamza.policy.PolicyEngine;
import io.envoyproxy.envoy.service.ext_proc.v3.ProcessingRequest;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;
import java.lang.reflect.Modifier;

import static org.assertj.core.api.Assertions.assertThat;

class TurnPipelineContractTest {

    @Test
    void grpcServiceDependsOnPipelineRatherThanPolicyPersistenceOrMetrics() {
        Set<Class<?>> fieldTypes = Arrays.stream(ExternalProcessorService.class.getDeclaredFields())
                .filter(field -> !Modifier.isStatic(field.getModifiers()))
                .map(java.lang.reflect.Field::getType)
                .collect(java.util.stream.Collectors.toSet());

        assertThat(fieldTypes).containsExactlyInAnyOrder(
                TurnPipeline.class, CoachResponder.class);
        assertThat(fieldTypes).doesNotContain(PolicyEngine.class, TurnRepository.class,
                HamzaMetrics.class, ReEncodedContentDetector.class,
                ManagedContinuationRuntime.class);
    }

    @Test
    void plainJavaPipelineContractContainsNoGrpcOrEnvoyTypes() {
        assertThat(Arrays.stream(TurnPipeline.class.getDeclaredMethods())
                .flatMap(method -> java.util.stream.Stream.concat(
                        java.util.stream.Stream.of(method.getReturnType()),
                        Arrays.stream(method.getParameterTypes())))
                .map(Class::getName))
                .noneMatch(name -> name.startsWith("io.grpc")
                        || name.startsWith("io.envoyproxy"));
        assertThat(ProcessingRequest.class.getName()).startsWith("io.envoyproxy");
    }

    @Test
    void providerResponseRetentionIsOneMiBAndClosesExplicitly() {
        TurnState state = new TurnState();
        byte[] oversized = new byte[TurnState.MAX_RESPONSE_BYTES + 17];

        state.appendResponseBody(oversized);

        assertThat(state.retainedResponseBytes()).isEqualTo(1024 * 1024);
        assertThat(state.responseTruncated()).isTrue();
        state.close();
        assertThat(state.retainedResponseBytes()).isZero();
    }
}
