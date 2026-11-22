package com.cantalay.authgateway.controller;

import com.cantalay.authgateway.account.AccountActionService;
import com.cantalay.authgateway.account.ClientIp;
import com.cantalay.authgateway.domain.ActionTokenRequest;
import com.cantalay.authgateway.domain.ForgotPasswordRequest;
import com.cantalay.authgateway.domain.ResendVerificationRequest;
import com.cantalay.authgateway.domain.ResetPasswordRequest;
import com.cantalay.authgateway.domain.TokenResponseDto;
import com.cantalay.authgateway.realm.RealmConfig;
import com.cantalay.authgateway.realm.RealmRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Forgot/reset password and email confirmation without Keycloak pages: emails link into the application, which posts
 * the link's token here. Served at {@code /auth/{realm}/...} and, for the default realm, {@code /auth/...}.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AccountController {

    private final AccountActionService accountActions;
    private final RealmRegistry realms;

    /** Always 202, whether or not the address has an account. */
    @PostMapping({"/forgot-password", "/{realm}/forgot-password"})
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void forgotPassword(@PathVariable(required = false) String realm,
                               @Valid @RequestBody ForgotPasswordRequest request,
                               HttpServletRequest http) {
        RealmConfig config = realms.resolve(realm);
        accountActions.forgotPassword(config, request.email(), request.locale(), ClientIp.of(http));
    }

    /** 204 while the reset link is usable; 410 {@code reset_token_invalid} otherwise. */
    @PostMapping({"/reset-password/check", "/{realm}/reset-password/check"})
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void checkResetToken(@PathVariable(required = false) String realm,
                                @Valid @RequestBody ActionTokenRequest request,
                                HttpServletRequest http) {
        accountActions.checkResetToken(realms.resolve(realm), request.token(), ClientIp.of(http));
    }

    /** 200 with the tokens of a new session on this device; 204 if the password changed but the sign-in did not. */
    @PostMapping({"/reset-password", "/{realm}/reset-password"})
    public ResponseEntity<TokenResponseDto> resetPassword(@PathVariable(required = false) String realm,
                                                          @Valid @RequestBody ResetPasswordRequest request,
                                                          HttpServletRequest http) {
        return accountActions.resetPassword(realms.resolve(realm), request.token(), request.newPassword(), ClientIp.of(http))
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.noContent().build());
    }

    /** Always 202; an unverified account gets a new confirmation email (at most one a minute). */
    @PostMapping({"/resend-verification", "/{realm}/resend-verification"})
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void resendVerification(@PathVariable(required = false) String realm,
                                   @Valid @RequestBody ResendVerificationRequest request,
                                   HttpServletRequest http) {
        RealmConfig config = realms.resolve(realm);
        accountActions.resendVerification(config, request.email(), request.locale(), ClientIp.of(http));
    }

    /** 204 (also when already confirmed); 410 {@code verify_token_invalid}. The client then refreshes its token. */
    @PostMapping({"/verify-email", "/{realm}/verify-email"})
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void verifyEmail(@PathVariable(required = false) String realm,
                            @Valid @RequestBody ActionTokenRequest request,
                            HttpServletRequest http) {
        accountActions.verifyEmail(realms.resolve(realm), request.token(), ClientIp.of(http));
    }
}
