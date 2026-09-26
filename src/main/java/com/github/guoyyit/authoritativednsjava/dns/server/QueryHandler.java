package com.github.guoyyit.authoritativednsjava.dns.server;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsHeader;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RCode;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Builds authoritative answers: AA answers with CNAME chasing, delegation,
 * NXDOMAIN and NODATA (type-not-present); the latter two carry the SOA in the
 * authority section with proper TTLs.
 */
@Component
public class QueryHandler {

    private static final int CLASS_IN = 1;
    private static final int MAX_CNAME_CHAIN = 16;

    private final ZoneStore store;

    public QueryHandler(ZoneStore store) {
        this.store = store;
    }

    public DnsMessage handle(DnsMessage query) {
        DnsMessage resp = newResponse(query);
        DnsHeader h = resp.getHeader();

        Optional<Zone> maybeZone = store.current();
        if (maybeZone.isEmpty()) {
            h.setRcode(RCode.SERVFAIL);
            return resp;
        }
        Zone zone = maybeZone.get();
        if (query.getQuestions().isEmpty()) {
            return resp; // NOERROR empty
        }
        DnsQuestion q = query.getQuestions().get(0);
        if (q.qclass() != CLASS_IN) {
            h.setRcode(RCode.REFUSED);
            return resp;
        }

        // Delegation: deepest ancestor below the zone apex that owns NS records wins.
        Optional<DnsName> delegation = findDelegation(zone, q.name());
        if (delegation.isPresent()) {
            answerDelegation(resp, zone, delegation.get());
            return resp;
        }

        h.setAa(true);

        if (!zone.contains(q.name())) {
            h.setRcode(RCode.NXDOMAIN);
            addSoa(resp, zone);
            return resp;
        }

        List<DnsRecord> answers = resp.getAnswers();
        DnsName current = q.name();
        Set<DnsName> seen = new HashSet<>();

        for (int depth = 0; depth <= MAX_CNAME_CHAIN; depth++) {
            if (!seen.add(current)) {
                break; // loop guard
            }
            List<DnsRecord> atName = zone.lookup(current);
            if (atName.isEmpty()) {
                h.setRcode(RCode.NXDOMAIN);
                addSoa(resp, zone);
                return resp;
            }
            List<DnsRecord> direct = zone.lookup(current, q.type());
            if (!direct.isEmpty() || q.type() == DnsRecordType.ANY) {
                if (q.type() == DnsRecordType.ANY) {
                    answers.addAll(atName);
                } else {
                    answers.addAll(direct);
                }
                return resp;
            }
            // Type not present; chase CNAME if the name owns one.
            List<DnsRecord> cnames = zone.lookup(current, DnsRecordType.CNAME);
            if (cnames.isEmpty()) {
                // Name exists but the requested type does not: NOERROR empty + SOA.
                addSoa(resp, zone);
                return resp;
            }
            DnsRecord cname = cnames.get(0);
            answers.add(cname);
            current = RData.nameFromRdata(cname.getRdata());
        }
        h.setRcode(RCode.SERVFAIL);
        return resp;
    }

    private Optional<DnsName> findDelegation(Zone zone, DnsName name) {
        DnsName n = name;
        while (n != null && n.isSubdomainOf(zone.getOrigin()) && !n.equals(zone.getOrigin())) {
            if (!zone.lookup(n, DnsRecordType.NS).isEmpty()) {
                return Optional.of(n);
            }
            n = n.parent();
        }
        return Optional.empty();
    }

    private void answerDelegation(DnsMessage resp, Zone zone, DnsName cut) {
        // Non-authoritative referral: AA clear, NS RRset in authority, glue in additional.
        for (DnsRecord ns : zone.lookup(cut, DnsRecordType.NS)) {
            resp.getAuthorities().add(ns);
            DnsName target = RData.nameFromRdata(ns.getRdata());
            for (DnsRecord glueA : zone.lookup(target, DnsRecordType.A)) {
                resp.getAdditionals().add(glueA);
            }
            for (DnsRecord glueAAAA : zone.lookup(target, DnsRecordType.AAAA)) {
                resp.getAdditionals().add(glueAAAA);
            }
        }
    }

    private void addSoa(DnsMessage resp, Zone zone) {
        DnsRecord soa = zone.getSoa();
        // Negative responses carry the SOA with the SOA minimum TTL (RFC 2308).
        resp.getAuthorities().add(new DnsRecord(soa.getName(), soa.getType(), soa.getRrclass(),
                zone.getNegativeTtl(), soa.getRdata()));
    }

    private DnsMessage newResponse(DnsMessage query) {
        DnsMessage resp = new DnsMessage();
        DnsHeader qh = query.getHeader();
        DnsHeader h = resp.getHeader();
        h.setId(qh.getId());
        h.setQr(true);
        h.setOpcode(qh.getOpcode());
        h.setRd(qh.isRd());
        h.setRa(true);
        if (!query.getQuestions().isEmpty()) {
            resp.getQuestions().addAll(query.getQuestions());
        }
        return resp;
    }
}
