package com.cantalay.authgateway.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Background work of the account email endpoints (user lookup and SMTP), so their responses never depend on whether the
 * address exists. Bounded: when the queue is full the work is dropped and logged; the client still gets 202.
 */
@Configuration
public class AccountTaskConfig {

    private static final Logger log = LoggerFactory.getLogger(AccountTaskConfig.class);

    @Bean(name = "accountTaskExecutor")
    ThreadPoolTaskExecutor accountTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setThreadNamePrefix("account-");
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(500);
        executor.setRejectedExecutionHandler((task, pool) -> log.error("Account email queue full; task dropped"));
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.setAwaitTerminationSeconds(20);
        return executor;
    }
}
