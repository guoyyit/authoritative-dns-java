package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RCode;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.QueryHandler;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Authoritative answer semantics: AA, NXDOMAIN, NODATA+SOA, CNAME, delegation. */
class QueryHandlerTest {

    private static final int IN = 1;
    private ZoneStore store;
    private QueryHandler handler;

    @BeforeEach
    void setUp() {
        store = new ZoneStore();
        DnsName origin = DnsName.of("example.test.");
        Zone zone = Zone.builder(origin)
                .add(new DnsRecord(origin, DnsRecordType.SOA, IN, 3600,
                        RData.soaRdata(DnsName.of("ns.example.test."),
                                DnsName.of("hm.example.test."), 1, 7200, 3600, 100, 60)))
                .add(new DnsRecord(origin, DnsRecordType.NS, IN, 3600,
                        RData.nameRdata(DnsName.of("ns.example.test."))))
                .add(new DnsRecord(DnsName.of("ns.example.test."), DnsRecordType.A, IN, 300,
                        RData.aRdata("127.0.0.1")))
                .add(new DnsRecord(DnsName.of("www.example.test."), DnsRecordType.A, IN, 300,
                        RData.aRdata("127.0.0.2")))
                .add(new DnsRecord(DnsName.of("alias.example.test."), DnsRecordType.CNAME, IN, 300,
                        RData.nameRdata(DnsName.of("www.example.test."))))
                .add(new DnsRecord(DnsName.of("only-a.example.test."), DnsRecordType.A, IN, 300,
                        RData.aRdata("127.0.0.9")))
                .add(new DnsRecord(DnsName.of("sub.example.test."), DnsRecordType.NS, IN, 3600,
                        RData.nameRdata(DnsName.of("ns.sub.example.test."))))
                .add(new DnsRecord(DnsName.of("ns.sub.example.test."), DnsRecordType.A, IN, 3600,
                        RData.aRdata("127.0.0.4")))
                .build();
        store.replace(zone);
        handler = new QueryHandler(store);
    }

    private DnsMessage query(String name, int type) {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(100);
        q.getQuestions().add(new DnsQuestion(DnsName.of(name), type, IN));
        return q;
    }

    @Test
    void authoritativeAnswerForA() {
        DnsMessage resp = handler.handle(query("www.example.test.", DnsRecordType.A));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertTrue(resp.getHeader().isAa());
        assertEquals(1, resp.getAnswers().size());
        assertEquals(DnsRecordType.A, resp.getAnswers().get(0).getType());
    }

    @Test
    void nxdomainCarriesSoaWithMinimumTtl() {
        DnsMessage resp = handler.handle(query("nope.example.test.", DnsRecordType.A));
        assertEquals(RCode.NXDOMAIN, resp.getHeader().getRcode());
        assertTrue(resp.getHeader().isAa());
        assertTrue(resp.getAnswers().isEmpty());
        assertEquals(1, resp.getAuthorities().size());
        DnsRecord soa = resp.getAuthorities().get(0);
        assertEquals(DnsRecordType.SOA, soa.getType());
        assertEquals(60, soa.getTtl()); // SOA minimum
    }

    @Test
    void nodataIsNoerrorEmptyAnswerWithSoa() {
        DnsMessage resp = handler.handle(query("only-a.example.test.", DnsRecordType.AAAA));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertTrue(resp.getAnswers().isEmpty());
        assertEquals(1, resp.getAuthorities().size());
        assertEquals(DnsRecordType.SOA, resp.getAuthorities().get(0).getType());
        assertEquals(60, resp.getAuthorities().get(0).getTtl());
    }

    @Test
    void cnameIsChasedToTargetA() {
        DnsMessage resp = handler.handle(query("alias.example.test.", DnsRecordType.A));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertEquals(2, resp.getAnswers().size());
        assertEquals(DnsRecordType.CNAME, resp.getAnswers().get(0).getType());
        assertEquals(DnsRecordType.A, resp.getAnswers().get(1).getType());
        assertEquals(DnsName.of("www.example.test."),
                RData.nameFromRdata(resp.getAnswers().get(0).getRdata()));
    }

    @Test
    void delegationReturnsReferralWithoutAaAndWithGlue() {
        DnsMessage resp = handler.handle(query("host.sub.example.test.", DnsRecordType.A));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertFalse(resp.getHeader().isAa());
        assertTrue(resp.getAnswers().isEmpty());
        List<DnsRecord> ns = resp.getAuthorities();
        assertEquals(1, ns.size());
        assertEquals(DnsRecordType.NS, ns.get(0).getType());
        assertEquals(1, resp.getAdditionals().size());
        assertEquals(DnsRecordType.A, resp.getAdditionals().get(0).getType());
        assertEquals(DnsName.of("ns.sub.example.test."),
                resp.getAdditionals().get(0).getName());
    }

    @Test
    void unknownTypeAtExistingNameIsNodata() {
        DnsMessage resp = handler.handle(query("www.example.test.", 99));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertTrue(resp.getAnswers().isEmpty());
        assertEquals(DnsRecordType.SOA, resp.getAuthorities().get(0).getType());
    }

    @Test
    void anyReturnsAllRecordsAtName() {
        DnsMessage resp = handler.handle(query("www.example.test.", DnsRecordType.ANY));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertEquals(1, resp.getAnswers().size());
    }
}
