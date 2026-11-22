package com.cantalay.authgateway.configuration;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Background work of the account email endpoints (user lookup and SMTP), so their responses never depend on whether the
 * address exists. Bounded: when the queue is full the work is dropped, logged and counted
 * ({@code auth_gateway_account_tasks_rejected_total}); the client still gets 202.
 */
@Configuration
public class AccountTaskConfig {

    private static final Logger log = LoggerFactory.getLogger(AccountTaskConfig.class);

    @Bean(name = "accountTaskExecutor")
    ThreadPoolTaskExecutor accountTaskExecutor(MeterRegistry meters) {
        Counter rejected = Counter.builder("auth.gateway.account.tasks.rejected")
                .description("Account email tasks dropped because the queue was full")
                .register(meters);
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setThreadNamePrefix("account-");
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(500);
        executor.setRejectedExecutionHandler((task, pool) -> {
            rejected.increment();
            log.error("Account email queue full; task dropped");
        });
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(20);
        return executor;
    }
}
