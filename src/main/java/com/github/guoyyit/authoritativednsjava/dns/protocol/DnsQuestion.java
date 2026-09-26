package com.github.guoyyit.authoritativednsjava.dns.protocol;

/** One question-section entry. */
public record DnsQuestion(DnsName name, int type, int qclass) {
}
