package com.github.guoyyit.authoritativednsjava.dns.protocol;

/** DNS response codes (RFC 1035 §4.1.1). */
public enum RCode {
    NOERROR(0),
    FORMERR(1),
    SERVFAIL(2),
    NXDOMAIN(3),
    NOTIMP(4),
    REFUSED(5);

    private final int code;

    RCode(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static RCode fromCode(int code) {
        for (RCode r : values()) {
            if (r.code == code) {
                return r;
            }
        }
        return NOERROR;
    }
}
