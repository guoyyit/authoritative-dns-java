package com.github.guoyyit.authoritativednsjava.dns.protocol;

/** Mutable DNS message header (RFC 1035 4.1.1). */
public final class DnsHeader {
    private int id;
    private boolean qr;
    private int opcode;
    private boolean aa;
    private boolean tc;
    private boolean rd;
    private boolean ra;
    private RCode rcode = RCode.NOERROR;
    private int qdCount;
    private int anCount;
    private int nsCount;
    private int arCount;

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public boolean isQr() { return qr; }
    public void setQr(boolean qr) { this.qr = qr; }
    public int getOpcode() { return opcode; }
    public void setOpcode(int opcode) { this.opcode = opcode; }
    public boolean isAa() { return aa; }
    public void setAa(boolean aa) { this.aa = aa; }
    public boolean isTc() { return tc; }
    public void setTc(boolean tc) { this.tc = tc; }
    public boolean isRd() { return rd; }
    public void setRd(boolean rd) { this.rd = rd; }
    public boolean isRa() { return ra; }
    public void setRa(boolean ra) { this.ra = ra; }
    public RCode getRcode() { return rcode; }
    public void setRcode(RCode rcode) { this.rcode = rcode; }
    public int getQdCount() { return qdCount; }
    public void setQdCount(int qdCount) { this.qdCount = qdCount; }
    public int getAnCount() { return anCount; }
    public void setAnCount(int anCount) { this.anCount = anCount; }
    public int getNsCount() { return nsCount; }
    public void setNsCount(int nsCount) { this.nsCount = nsCount; }
    public int getArCount() { return arCount; }
    public void setArCount(int arCount) { this.arCount = arCount; }
}
