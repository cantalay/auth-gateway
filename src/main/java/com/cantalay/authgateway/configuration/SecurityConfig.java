package com.cantalay.authgateway.configuration;

import com.cantalay.authgateway.realm.RealmConfig;
import com.cantalay.authgateway.realm.RealmRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    private final List<String> allowedOrigins;

    SecurityConfig(@Value("#{'${CORS_ALLOWED_ORIGINS:http://localhost:3000,http://localhost:5173,http://localhost:8081,https://todogi.singlestranger.com,https://www.todogi.singlestranger.com}'.split(',')}") List<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins.stream().map(String::trim).filter(origin -> !origin.isEmpty()).toList();
    }

    /** Accepts access tokens from every configured realm; controllers check the token realm against the path. */
    @Bean
    JwtIssuerAuthenticationManagerResolver jwtIssuerResolver(RealmRegistry realms) {
        return JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers(
                realms.all().stream().map(RealmConfig::issuerUri).toList()
        );
    }

    @Bean
    SecurityFilterChain security(HttpSecurity http, JwtIssuerAuthenticationManagerResolver jwtIssuerResolver) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(s ->
                        s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/auth/login", "/auth/*/login",
                                "/auth/register", "/auth/*/register",
                                "/auth/resend-verification", "/auth/*/resend-verification",
                                "/auth/refresh", "/auth/*/refresh",
                                "/auth/social", "/auth/*/social",
                                "/actuator/health",
                                "/actuator/health/**",
                                "/actuator/info",
                                "/actuator/prometheus"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 ->
                        oauth2.authenticationManagerResolver(jwtIssuerResolver)
                );

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        config.setAllowedOrigins(allowedOrigins);

        config.setAllowedMethods(List.of(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        ));

        config.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "X-Requested-With"
        ));

        config.setExposedHeaders(List.of(
                "Authorization"
        ));

        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
