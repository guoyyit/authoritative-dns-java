package com.github.guoyyit.authoritativednsjava.dns.zone;

/** Raised when persisted zone data is missing, corrupt, or cannot be written. */
public class ZonePersistenceException extends Exception {
    public ZonePersistenceException(String message) {
        super(message);
    }

    public ZonePersistenceException(String message, Throwable cause) {
        super(message, cause);
    }
}
