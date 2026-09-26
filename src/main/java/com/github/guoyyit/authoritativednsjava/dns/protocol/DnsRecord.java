package com.github.guoyyit.authoritativednsjava.dns.protocol;

import java.util.Arrays;

/** One resource record. {@code rdata} holds wire-format RDATA (uncompressed). */
public final class DnsRecord {
    private final DnsName name;
    private final int type;
    private final int rrclass;
    private final long ttl;
    private final byte[] rdata;

    public DnsRecord(DnsName name, int type, int rrclass, long ttl, byte[] rdata) {
        this.name = name;
        this.type = type;
        this.rrclass = rrclass;
        this.ttl = ttl;
        this.rdata = rdata == null ? new byte[0] : rdata.clone();
    }

    public DnsName getName() { return name; }
    public int getType() { return type; }
    public int getRrclass() { return rrclass; }
    public long getTtl() { return ttl; }
    public byte[] getRdata() { return rdata.clone(); }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof DnsRecord other)) {
            return false;
        }
        return name.equals(other.name)
                && type == other.type
                && rrclass == other.rrclass
                && ttl == other.ttl
                && Arrays.equals(rdata, other.rdata);
    }

    @Override
    public int hashCode() {
        int h = name.hashCode();
        h = 31 * h + type;
        h = 31 * h + rrclass;
        h = 31 * h + Long.hashCode(ttl);
        h = 31 * h + Arrays.hashCode(rdata);
        return h;
    }

    @Override
    public String toString() {
        return name + " " + ttl + " " + DnsRecordType.name(type);
    }
}
