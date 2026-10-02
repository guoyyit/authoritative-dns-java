package com.github.guoyyit.authoritativednsjava.dns.protocol;

import java.util.Locale;

/**
 * Well-known DNS record type codes. Unknown types are kept as raw codes and
 * never cause a whole message to fail.
 */
public final class DnsRecordType {
    /** Largest legal TYPE code: the wire field is 16 bits (RFC 1035 §3.2.2). */
    public static final int MAX_CODE = 0xFFFF;

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
     * (RFC 3597). The numeric code after "TYPE" is parsed in full: no digit
     * may be dropped, and the value must fit the 16-bit wire field. Anything
     * malformed or out of range is rejected with {@link IllegalArgumentException}.
     */
    public static int parse(String text) {
        if (text == null) {
            throw new IllegalArgumentException("record type must not be null");
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
                    yield parseTypeCode(text, upper.substring(4));
                }
                throw new IllegalArgumentException("unknown record type: " + text);
            }
        };
    }

    private static int parseTypeCode(String original, String digits) {
        if (digits.isEmpty()) {
            throw new IllegalArgumentException("missing type code in: " + original);
        }
        for (int i = 0; i < digits.length(); i++) {
            char c = digits.charAt(i);
            if (c < '0' || c > '9') {
                throw new IllegalArgumentException(
                        "malformed type code (digits only) in: " + original);
            }
        }
        final int code;
        try {
            code = Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "type code out of range (0-" + MAX_CODE + ") in: " + original, e);
        }
        if (code > MAX_CODE) {
            throw new IllegalArgumentException(
                    "type code out of range (0-" + MAX_CODE + ") in: " + original);
        }
        return code;
    }
}
