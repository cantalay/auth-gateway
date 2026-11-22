package com.cantalay.authgateway.action;

/** The token was not issued by this gateway for this realm and purpose, or it has expired. */
public class InvalidActionTokenException extends RuntimeException {

    public enum Reason { INVALID, EXPIRED }

    private final Reason reason;

    public InvalidActionTokenException(Reason reason) {
        super(reason == Reason.EXPIRED ? "Action token expired" : "Action token invalid", null, false, false);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
