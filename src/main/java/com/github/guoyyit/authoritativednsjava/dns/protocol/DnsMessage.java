package com.github.guoyyit.authoritativednsjava.dns.protocol;

import java.util.ArrayList;
import java.util.List;

/** A full DNS message: header plus four sections. */
public final class DnsMessage {
    private final DnsHeader header = new DnsHeader();
    private final List<DnsQuestion> questions = new ArrayList<>();
    private final List<DnsRecord> answers = new ArrayList<>();
    private final List<DnsRecord> authorities = new ArrayList<>();
    private final List<DnsRecord> additionals = new ArrayList<>();

    public DnsHeader getHeader() { return header; }
    public List<DnsQuestion> getQuestions() { return questions; }
    public List<DnsRecord> getAnswers() { return answers; }
    public List<DnsRecord> getAuthorities() { return authorities; }
    public List<DnsRecord> getAdditionals() { return additionals; }
}
