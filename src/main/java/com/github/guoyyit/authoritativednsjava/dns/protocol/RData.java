package com.github.guoyyit.authoritativednsjava.dns.protocol;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Builders and parsers for RDATA of well-known record types (uncompressed wire form). */
public final class RData {

    private RData() {
    }

    // ------------------------------------------------------------ builders

    public static byte[] aRdata(String ipv4) {
        String[] parts = ipv4.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("bad IPv4 address: " + ipv4);
        }
        byte[] out = new byte[4];
        for (int i = 0; i < 4; i++) {
            int v = Integer.parseInt(parts[i]);
            if (v < 0 || v > 255) {
                throw new IllegalArgumentException("bad IPv4 address: " + ipv4);
            }
            out[i] = (byte) v;
        }
        return out;
    }

    public static byte[] aaaaRdata(String ipv6) {
        try {
            byte[] addr = InetAddress.getByName(ipv6).getAddress();
            if (addr.length != 16) {
                throw new IllegalArgumentException("not an IPv6 address: " + ipv6);
            }
            return addr;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("bad IPv6 address: " + ipv6, e);
        }
    }

    public static byte[] nameRdata(DnsName name) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writeNameUncompressed(buf, name);
        return buf.toByteArray();
    }

    public static byte[] mxRdata(int preference, DnsName exchange) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        DnsMessageCodec.writeU16(buf, preference);
        writeNameUncompressed(buf, exchange);
        return buf.toByteArray();
    }

    public static byte[] soaRdata(DnsName mname, DnsName rname, long serial,
                                  long refresh, long retry, long expire, long minimum) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writeNameUncompressed(buf, mname);
        writeNameUncompressed(buf, rname);
        DnsMessageCodec.writeU32(buf, serial);
        DnsMessageCodec.writeU32(buf, refresh);
        DnsMessageCodec.writeU32(buf, retry);
        DnsMessageCodec.writeU32(buf, expire);
        DnsMessageCodec.writeU32(buf, minimum);
        return buf.toByteArray();
    }

    /** TXT RDATA: one or more character-strings, each length-prefixed (max 255). */
    public static byte[] txtRdata(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0) {
            return new byte[]{0};
        }
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int offset = 0;
        do {
            int chunk = Math.min(255, bytes.length - offset);
            buf.write(chunk);
            buf.write(bytes, offset, chunk);
            offset += chunk;
        } while (offset < bytes.length);
        return buf.toByteArray();
    }

    static void writeNameUncompressed(ByteArrayOutputStream buf, DnsName name) {
        for (String label : name.labels()) {
            byte[] b = label.getBytes(StandardCharsets.ISO_8859_1);
            buf.write(b.length);
            buf.write(b, 0, b.length);
        }
        buf.write(0);
    }

    // ------------------------------------------------------------ parsers (display / zone files)

    public static String toText(int type, byte[] rdata) {
        int[] pos = {0};
        return switch (type) {
            case DnsRecordType.A -> rdata.length == 4
                    ? (rdata[0] & 0xFF) + "." + (rdata[1] & 0xFF) + "."
                    + (rdata[2] & 0xFF) + "." + (rdata[3] & 0xFF)
                    : hex(rdata);
            case DnsRecordType.AAAA -> {
                try {
                    yield InetAddress.getByAddress(rdata).getHostAddress();
                } catch (Exception e) {
                    yield hex(rdata);
                }
            }
            case DnsRecordType.NS, DnsRecordType.CNAME, DnsRecordType.PTR ->
                    readNameFrom(rdata, pos).toString();
            case DnsRecordType.MX -> {
                int pref = u16(rdata, pos);
                yield pref + " " + readNameFrom(rdata, pos);
            }
            case DnsRecordType.SOA -> {
                DnsName mname = readNameFrom(rdata, pos);
                DnsName rname = readNameFrom(rdata, pos);
                long serial = u32(rdata, pos);
                long refresh = u32(rdata, pos);
                long retry = u32(rdata, pos);
                long expire = u32(rdata, pos);
                long minimum = u32(rdata, pos);
                yield mname + " " + rname + " " + serial + " " + refresh + " " + retry
                        + " " + expire + " " + minimum;
            }
            case DnsRecordType.TXT -> {
                StringBuilder sb = new StringBuilder();
                while (pos[0] < rdata.length) {
                    int len = rdata[pos[0]++] & 0xFF;
                    if (pos[0] + len > rdata.length) {
                        break;
                    }
                    if (sb.length() > 0) {
                        sb.append(' ');
                    }
                    String chunk = new String(rdata, pos[0], len, StandardCharsets.UTF_8);
                    sb.append('"').append(chunk.replace("\\", "\\\\").replace("\"", "\\\""))
                            .append('"');
                    pos[0] += len;
                }
                yield sb.toString();
            }
            default -> hex(rdata);
        };
    }

    public static DnsName nameFromRdata(byte[] rdata) {
        return readNameFrom(rdata, new int[]{0});
    }

    /** Parses the text form produced by {@link #toText} back into wire RDATA. */
    public static byte[] fromText(int type, String text) {
        String[] tokens = text.trim().split("\\s+");
        return switch (type) {
            case DnsRecordType.A -> aRdata(tokens[0]);
            case DnsRecordType.AAAA -> aaaaRdata(tokens[0]);
            case DnsRecordType.NS, DnsRecordType.CNAME, DnsRecordType.PTR ->
                    nameRdata(DnsName.of(tokens[0]));
            case DnsRecordType.MX -> mxRdata(Integer.parseInt(tokens[0]), DnsName.of(tokens[1]));
            case DnsRecordType.SOA -> soaRdata(DnsName.of(tokens[0]), DnsName.of(tokens[1]),
                    Long.parseLong(tokens[2]), Long.parseLong(tokens[3]),
                    Long.parseLong(tokens[4]), Long.parseLong(tokens[5]),
                    Long.parseLong(tokens[6]));
            case DnsRecordType.TXT -> parseTxt(text);
            default -> parseGeneric(text);
        };
    }

    /** Parses one or more quoted character-strings into TXT RDATA. */
    private static byte[] parseTxt(String text) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        StringBuilder sb = new StringBuilder();
        boolean inQuote = false;
        boolean escape = false;
        boolean sawAny = false;
        for (char c : text.toCharArray()) {
            if (escape) {
                sb.append(c);
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (c == '"') {
                if (inQuote) {
                    byte[] b = sb.toString().getBytes(StandardCharsets.UTF_8);
                    if (b.length > 255) {
                        throw new IllegalArgumentException("TXT chunk too long");
                    }
                    buf.write(b.length);
                    buf.write(b, 0, b.length);
                    sb.setLength(0);
                    sawAny = true;
                }
                inQuote = !inQuote;
            } else if (inQuote) {
                sb.append(c);
            }
        }
        if (inQuote) {
            throw new IllegalArgumentException("unterminated quoted string in TXT RDATA");
        }
        if (!sawAny) {
            // Allow bare text: treat the whole trimmed value as one character-string.
            return txtRdata(text.trim());
        }
        return buf.toByteArray();
    }

    /** RFC 3597 generic form: {@code \# <len> <hex bytes>}. */
    private static byte[] parseGeneric(String text) {
        if (!text.startsWith("\\#")) {
            throw new IllegalArgumentException("unknown-type RDATA must use \\# form");
        }
        String[] t = text.trim().split("\\s+");
        int len = Integer.parseInt(t[1]);
        if (t.length != 2 + len) {
            throw new IllegalArgumentException("generic RDATA length mismatch");
        }
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) Integer.parseInt(t[2 + i], 16);
        }
        return out;
    }

    public static long soaSerial(byte[] soaRdata) {
        int[] pos = {0};
        readNameFrom(soaRdata, pos);
        readNameFrom(soaRdata, pos);
        return u32(soaRdata, pos);
    }

    public static long soaMinimum(byte[] soaRdata) {
        int[] pos = {0};
        readNameFrom(soaRdata, pos);
        readNameFrom(soaRdata, pos);
        u32(soaRdata, pos); // serial
        u32(soaRdata, pos); // refresh
        u32(soaRdata, pos); // retry
        u32(soaRdata, pos); // expire
        return u32(soaRdata, pos);
    }

    private static DnsName readNameFrom(byte[] rdata, int[] pos) {
        List<String> labels = new ArrayList<>();
        while (pos[0] < rdata.length) {
            int len = rdata[pos[0]++] & 0xFF;
            if (len == 0) {
                break;
            }
            if (pos[0] + len > rdata.length) {
                throw new IllegalArgumentException("bad name in RDATA");
            }
            labels.add(new String(rdata, pos[0], len, StandardCharsets.ISO_8859_1));
            pos[0] += len;
        }
        return DnsName.ofLabels(labels);
    }

    private static int u16(byte[] d, int[] pos) {
        int v = ((d[pos[0]] & 0xFF) << 8) | (d[pos[0] + 1] & 0xFF);
        pos[0] += 2;
        return v;
    }

    private static long u32(byte[] d, int[] pos) {
        long v = ((long) (d[pos[0]] & 0xFF) << 24) | ((d[pos[0] + 1] & 0xFF) << 16)
                | ((d[pos[0] + 2] & 0xFF) << 8) | (d[pos[0] + 3] & 0xFF);
        pos[0] += 4;
        return v;
    }

    private static String hex(byte[] d) {
        StringBuilder sb = new StringBuilder("\\# ");
        sb.append(d.length);
        for (byte b : d) {
            sb.append(String.format(" %02x", b));
        }
        return sb.toString();
    }
}
