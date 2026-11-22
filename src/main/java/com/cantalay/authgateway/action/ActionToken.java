package com.cantalay.authgateway.action;

/**
 * Verified contents of an action token.
 *
 * @param realm       realm the token was issued for
 * @param purpose     {@link ActionPurpose}
 * @param subject     Keycloak user id
 * @param expiresAt   expiry, epoch seconds
 * @param fingerprint state of the account when the token was issued; the caller compares it with the current state
 *                    (single use without server-side storage)
 */
public record ActionToken(String realm, ActionPurpose purpose, String subject, long expiresAt, String fingerprint) {
}
