package com.cantalay.authgateway.domain;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * {@code POST /social}: the {@code code} the provider sign-in returned to the app, or, when Keycloak refused the sign-in
 * and the app's redirect got {@code error} / {@code error_description} instead of a code, those two (the gateway
 * translates them, e.g. {@code account_exists_unverified} → 409). {@code code} is required unless {@code error} is
 * given.
 *
 * @param mode             {@code login} (also when absent): sign in with the provider; {@code link}: add the provider to
 *                         the account of the request's Bearer token (realms with identity methods only)
 * @param provider         identity provider alias the app started the sign-in with ({@code kc_idp_hint}: google, apple);
 *                         required for {@code mode=link}, where the code must prove a fresh sign-in with it
 * @param error            {@code error} of the app's redirect (no code then)
 * @param errorDescription {@code error_description} of the app's redirect
 */
@SocialLoginRequest.CodeOrError
public record SocialLoginRequest(
        String code,
        @NotBlank String redirectUri,
        String mode,
        @Size(max = 64) @Pattern(regexp = "[a-z0-9][a-z0-9-]*") String provider,
        @Size(max = 64) String error,
        @Size(max = 256) @JsonAlias("error_description") String errorDescription
) {
    public SocialLoginRequest(String code, String redirectUri) {
        this(code, redirectUri, null);
    }

    public SocialLoginRequest(String code, String redirectUri, String mode) {
        this(code, redirectUri, mode, null, null, null);
    }

    public SocialLoginRequest(String code, String redirectUri, String mode, String provider) {
        this(code, redirectUri, mode, provider, null, null);
    }

    /** Whether the app's redirect carried an error instead of a code. */
    public boolean isCallbackError() {
        return error != null && !error.isBlank();
    }

    /** {@code code} must not be blank unless {@code error} is given; reported on the {@code code} field like {@code @NotBlank}. */
    @Target(ElementType.TYPE)
    @Retention(RetentionPolicy.RUNTIME)
    @Constraint(validatedBy = CodeOrErrorValidator.class)
    public @interface CodeOrError {
        String message() default "{jakarta.validation.constraints.NotBlank.message}";

        Class<?>[] groups() default {};

        Class<? extends Payload>[] payload() default {};
    }

    public static final class CodeOrErrorValidator implements ConstraintValidator<CodeOrError, SocialLoginRequest> {
        @Override
        public boolean isValid(SocialLoginRequest request, ConstraintValidatorContext context) {
            if (request == null || request.isCallbackError() || (request.code() != null && !request.code().isBlank())) {
                return true;
            }
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                    .addPropertyNode("code").addConstraintViolation();
            return false;
        }
    }
}
