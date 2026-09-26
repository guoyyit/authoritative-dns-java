package com.github.guoyyit.authoritativednsjava.dns.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Wire-format codec (RFC 1035 section 4). Handles compressed names in both
 * directions. RDATA of well-known types (NS/CNAME/PTR/SOA/MX) is stored
 * internally in uncompressed wire form; unknown types are kept verbatim and
 * never fail parsing of the surrounding message.
 */
public final class DnsMessageCodec {

    private static final int HEADER_LEN = 12;
    private static final int MAX_POINTERS = 128;

    private DnsMessageCodec() {
    }

    // ---------------------------------------------------------------- decode

    public static DnsMessage decode(byte[] data) throws DnsParseException {
        if (data == null || data.length < HEADER_LEN) {
            throw new DnsParseException("message shorter than DNS header");
        }
        DnsMessage msg = new DnsMessage();
        DnsHeader h = msg.getHeader();
        int[] pos = {0};
        h.setId(readU16(data, pos));
        int flags = readU16(data, pos);
        h.setQr((flags & 0x8000) != 0);
        h.setOpcode((flags >> 11) & 0xF);
        h.setAa((flags & 0x0400) != 0);
        h.setTc((flags & 0x0200) != 0);
        h.setRd((flags & 0x0100) != 0);
        h.setRa((flags & 0x0080) != 0);
        h.setRcode(RCode.fromCode(flags & 0xF));
        int qd = readU16(data, pos);
        int an = readU16(data, pos);
        int ns = readU16(data, pos);
        int ar = readU16(data, pos);
        h.setQdCount(qd);
        h.setAnCount(an);
        h.setNsCount(ns);
        h.setArCount(ar);

        for (int i = 0; i < qd; i++) {
            DnsName name = readName(data, pos);
            int type = readU16(data, pos);
            int qclass = readU16(data, pos);
            msg.getQuestions().add(new DnsQuestion(name, type, qclass));
        }
        readRecords(data, pos, an, msg.getAnswers());
        readRecords(data, pos, ns, msg.getAuthorities());
        readRecords(data, pos, ar, msg.getAdditionals());
        if (pos[0] != data.length) {
            throw new DnsParseException("trailing bytes after DNS message");
        }
        return msg;
    }

    private static void readRecords(byte[] data, int[] pos, int count, List<DnsRecord> out)
            throws DnsParseException {
        for (int i = 0; i < count; i++) {
            DnsName name = readName(data, pos);
            int type = readU16(data, pos);
            int rrclass = readU16(data, pos);
            long ttl = readU32(data, pos);
            int rdlen = readU16(data, pos);
            if (pos[0] + rdlen > data.length) {
                throw new DnsParseException("RDATA overruns message");
            }
            int rdataStart = pos[0];
            pos[0] += rdlen;
            byte[] rdata = normalizeRdata(data, rdataStart, rdlen, type);
            out.add(new DnsRecord(name, type, rrclass, ttl, rdata));
        }
    }

    /**
     * Expands compressed names inside RDATA of well-known types so the stored
     * form is always uncompressed. Unknown types are copied verbatim.
     */
    private static byte[] normalizeRdata(byte[] data, int start, int len, int type)
            throws DnsParseException {
        try {
            switch (type) {
                case DnsRecordType.NS, DnsRecordType.CNAME, DnsRecordType.PTR -> {
                    int[] p = {start};
                    DnsName n = readName(data, p);
                    return RData.nameRdata(n);
                }
                case DnsRecordType.SOA -> {
                    int[] p = {start};
                    DnsName mname = readName(data, p);
                    DnsName rname = readName(data, p);
                    long serial = readU32(data, p);
                    long refresh = readU32(data, p);
                    long retry = readU32(data, p);
                    long expire = readU32(data, p);
                    long minimum = readU32(data, p);
                    return RData.soaRdata(mname, rname, serial, refresh, retry, expire, minimum);
                }
                case DnsRecordType.MX -> {
                    int[] p = {start};
                    int pref = readU16(data, p);
                    DnsName exchange = readName(data, p);
                    return RData.mxRdata(pref, exchange);
                }
                default -> {
                    byte[] raw = new byte[len];
                    System.arraycopy(data, start, raw, 0, len);
                    return raw;
                }
            }
        } catch (DnsParseException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new DnsParseException("malformed RDATA for type " + DnsRecordType.name(type), e);
        }
    }

    /** Reads a possibly-compressed name; {@code pos} advances past the name. */
    static DnsName readName(byte[] data, int[] pos) throws DnsParseException {
        List<String> labels = new ArrayList<>();
        Set<Integer> jumped = new HashSet<>();
        int p = pos[0];
        boolean jumpedOnce = false;
        int pointers = 0;
        while (true) {
            if (p >= data.length) {
                throw new DnsParseException("name overruns message");
            }
            int len = data[p] & 0xFF;
            if ((len & 0xC0) == 0xC0) {
                if (p + 1 >= data.length) {
                    throw new DnsParseException("truncated compression pointer");
                }
                int offset = ((len & 0x3F) << 8) | (data[p + 1] & 0xFF);
                if (offset >= data.length) {
                    throw new DnsParseException("compression pointer out of range");
                }
                if (!jumped.add(offset) || ++pointers > MAX_POINTERS) {
                    throw new DnsParseException("compression pointer loop");
                }
                if (!jumpedOnce) {
                    pos[0] = p + 2;
                    jumpedOnce = true;
                }
                p = offset;
            } else if ((len & 0xC0) != 0) {
                throw new DnsParseException("invalid label length bits");
            } else if (len == 0) {
                if (!jumpedOnce) {
                    pos[0] = p + 1;
                }
                break;
            } else {
                if (p + 1 + len > data.length) {
                    throw new DnsParseException("label overruns message");
                }
                labels.add(new String(data, p + 1, len, StandardCharsets.ISO_8859_1));
                p += 1 + len;
                if (!jumpedOnce) {
                    pos[0] = p;
                }
            }
        }
        return DnsName.ofLabels(labels);
    }

    // ---------------------------------------------------------------- encode

    public static byte[] encode(DnsMessage message) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(512);
        Map<List<String>, Integer> offsets = new HashMap<>();
        DnsHeader h = message.getHeader();
        writeU16(buf, h.getId());
        int flags = (h.isQr() ? 0x8000 : 0)
                | ((h.getOpcode() & 0xF) << 11)
                | (h.isAa() ? 0x0400 : 0)
                | (h.isTc() ? 0x0200 : 0)
                | (h.isRd() ? 0x0100 : 0)
                | (h.isRa() ? 0x0080 : 0)
                | (h.getRcode().code() & 0xF);
        writeU16(buf, flags);
        writeU16(buf, message.getQuestions().size());
        writeU16(buf, message.getAnswers().size());
        writeU16(buf, message.getAuthorities().size());
        writeU16(buf, message.getAdditionals().size());

        for (DnsQuestion q : message.getQuestions()) {
            writeName(buf, offsets, q.name());
            writeU16(buf, q.type());
            writeU16(buf, q.qclass());
        }
        writeRecords(buf, offsets, message.getAnswers());
        writeRecords(buf, offsets, message.getAuthorities());
        writeRecords(buf, offsets, message.getAdditionals());
        return buf.toByteArray();
    }

    private static void writeRecords(ByteArrayOutputStream buf, Map<List<String>, Integer> offsets,
                                     List<DnsRecord> records) {
        for (DnsRecord r : records) {
            writeName(buf, offsets, r.getName());
            writeU16(buf, r.getType());
            writeU16(buf, r.getRrclass());
            writeU32(buf, r.getTtl());
            byte[] rdata = r.getRdata();
            writeU16(buf, rdata.length);
            buf.write(rdata, 0, rdata.length);
        }
    }

    /** Writes a name, compressing suffixes already present in {@code offsets}. */
    static void writeName(ByteArrayOutputStream buf, Map<List<String>, Integer> offsets,
                          DnsName name) {
        List<String> labels = name.labels();
        int i = 0;
        while (i < labels.size()) {
            List<String> suffix = labels.subList(i, labels.size());
            Integer pointer = offsets.get(suffix);
            if (pointer != null) {
                writeU16(buf, 0xC000 | pointer);
                return;
            }
            if (buf.size() < 0x4000) {
                offsets.put(new ArrayList<>(suffix), buf.size());
            }
            byte[] label = labels.get(i).getBytes(StandardCharsets.ISO_8859_1);
            buf.write(label.length);
            buf.write(label, 0, label.length);
            i++;
        }
        buf.write(0);
    }

    // ---------------------------------------------------------------- primitives

    static int readU16(byte[] data, int[] pos) throws DnsParseException {
        if (pos[0] + 2 > data.length) {
            throw new DnsParseException("unexpected end of message");
        }
        int v = ((data[pos[0]] & 0xFF) << 8) | (data[pos[0] + 1] & 0xFF);
        pos[0] += 2;
        return v;
    }

    static long readU32(byte[] data, int[] pos) throws DnsParseException {
        if (pos[0] + 4 > data.length) {
            throw new DnsParseException("unexpected end of message");
        }
        long v = ((long) (data[pos[0]] & 0xFF) << 24)
                | ((data[pos[0] + 1] & 0xFF) << 16)
                | ((data[pos[0] + 2] & 0xFF) << 8)
                | (data[pos[0] + 3] & 0xFF);
        pos[0] += 4;
        return v;
    }

    static void writeU16(ByteArrayOutputStream buf, int v) {
        buf.write((v >>> 8) & 0xFF);
        buf.write(v & 0xFF);
    }

    static void writeU32(ByteArrayOutputStream buf, long v) {
        buf.write((int) (v >>> 24) & 0xFF);
        buf.write((int) (v >>> 16) & 0xFF);
        buf.write((int) (v >>> 8) & 0xFF);
        buf.write((int) v & 0xFF);
    }
}
