package ai.hamza.config;

import io.grpc.netty.NettyServerBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.ServerBuilderCustomizer;

import java.util.concurrent.Executors;

/**
 * Runs ext_proc gRPC service callbacks on virtual threads. ext_proc streams are
 * long-lived and per-message work is small, so a virtual-thread-per-task executor fits:
 * cheap to scale, no pool tuning. Pairs with {@code spring.threads.virtual.enabled=true}.
 */
@Configuration(proxyBeanMethods = false)
public class VirtualThreadConfig {

    @Bean
    ServerBuilderCustomizer<NettyServerBuilder> virtualThreadExecutorCustomizer() {
        return builder -> builder.executor(Executors.newVirtualThreadPerTaskExecutor());
    }
}
