package com.github.guoyyit.authoritativednsjava.dns.protocol;

import java.util.Locale;

/**
 * Well-known DNS record type codes. Unknown types are kept as raw codes and
 * never cause a whole message to fail.
 */
public final class DnsRecordType {
    public static final int A = 1;
    public static final int NS = 2;
    public static final int CNAME = 5;
    public static final int SOA = 6;
    public static final int PTR = 12;
    public static final int MX = 15;
    public static final int TXT = 16;
    public static final int AAAA = 28;
    public static final int AXFR = 252;
    public static final int ANY = 255;

    private DnsRecordType() {
    }

    public static String name(int code) {
        return switch (code) {
            case A -> "A";
            case NS -> "NS";
            case CNAME -> "CNAME";
            case SOA -> "SOA";
            case PTR -> "PTR";
            case MX -> "MX";
            case TXT -> "TXT";
            case AAAA -> "AAAA";
            case AXFR -> "AXFR";
            case ANY -> "ANY";
            default -> "TYPE" + code;
        };
    }

    /**
     * Inverse of {@link #name(int)}; accepts "A", "AAAA", ..., or "TYPEnnn"
     * (RFC 3597). The numeric form is parsed in full: every digit after
     * "TYPE" is significant, and the value must fit the 16-bit type-code
     * range 0-65535. Malformed or out-of-range input is rejected with
     * {@link IllegalArgumentException}; it is never truncated or remapped.
     */
    public static int parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("missing record type");
        }
        String upper = text.toUpperCase(Locale.ROOT);
        return switch (upper) {
            case "A" -> A;
            case "NS" -> NS;
            case "CNAME" -> CNAME;
            case "SOA" -> SOA;
            case "PTR" -> PTR;
            case "MX" -> MX;
            case "TXT" -> TXT;
            case "AAAA" -> AAAA;
            case "AXFR" -> AXFR;
            case "ANY" -> ANY;
            default -> {
                if (upper.startsWith("TYPE")) {
                    yield parseTypeCode(upper.substring(4), text);
                }
                throw new IllegalArgumentException("unknown record type: " + text);
            }
        };
    }

    private static int parseTypeCode(String digits, String original) {
        if (digits.isEmpty()) {
            throw new IllegalArgumentException("missing type code: " + original);
        }
        for (int i = 0; i < digits.length(); i++) {
            char c = digits.charAt(i);
            if (c < '0' || c > '9') {
                throw new IllegalArgumentException("invalid type code: " + original);
            }
        }
        final long value;
        try {
            value = Long.parseLong(digits);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid type code: " + original, e);
        }
        if (value > 65535) {
            throw new IllegalArgumentException(
                    "type code out of range (0-65535): " + original);
        }
        return (int) value;
    }
}
