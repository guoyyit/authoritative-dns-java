package com.github.guoyyit.authoritativednsjava.dns.protocol;

/** Raised when a DNS wire message cannot be parsed. */
public class DnsParseException extends Exception {
    public DnsParseException(String message) {
        super(message);
    }

    public DnsParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
