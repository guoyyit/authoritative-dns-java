package com.github.guoyyit.authoritativednsjava.dns.protocol;

/** Well-known DNS record type codes. Unknown types are kept as raw codes. */
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

    /** Inverse of {@link #name(int)}; accepts "A", "AAAA", ..., or "TYPEnnn". */
    public static int parse(String text) {
        return switch (text.toUpperCase(java.util.Locale.ROOT)) {
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
                if (text.toUpperCase(java.util.Locale.ROOT).startsWith("TYPE")) {
                    yield Integer.parseInt(text.substring(4));
                }
                throw new IllegalArgumentException("unknown record type: " + text);
            }
        };
    }
}
