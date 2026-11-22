package com.cantalay.authgateway.configuration;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import static org.assertj.core.api.Assertions.assertThat;

class AccountTaskConfigTest {

    @Test
    void droppedTasksAreCounted() {
        SimpleMeterRegistry meters = new SimpleMeterRegistry();
        ThreadPoolTaskExecutor executor = new AccountTaskConfig().accountTaskExecutor(meters);
        executor.initialize();
        try {
            executor.getThreadPoolExecutor().getRejectedExecutionHandler().rejectedExecution(() -> { }, executor.getThreadPoolExecutor());
            assertThat(meters.find("auth.gateway.account.tasks.rejected").counter().count()).isEqualTo(1);
        } finally {
            executor.shutdown();
        }
    }
}
