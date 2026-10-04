package com.cantalay.authgateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableFeignClients
@ConfigurationPropertiesScan
@EnableAsync
public class AuthGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthGatewayApplication.class, args);
    }

}
