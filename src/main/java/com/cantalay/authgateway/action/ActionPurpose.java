package com.cantalay.authgateway.action;

/** What an action token may be used for; a token of one purpose is never accepted by the other endpoint. */
public enum ActionPurpose {
    RESET("reset"),
    VERIFY("verify");

    private final String value;

    ActionPurpose(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
