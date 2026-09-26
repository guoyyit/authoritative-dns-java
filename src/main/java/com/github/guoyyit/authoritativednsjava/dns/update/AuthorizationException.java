package com.github.guoyyit.authoritativednsjava.dns.update;

/** Raised when an update/transfer request presents no or a wrong key. */
public class AuthorizationException extends Exception {
    public AuthorizationException(String message) {
        super(message);
    }
}
