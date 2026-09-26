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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QueryHandlerTest {

    private static final DnsName ORIGIN = DnsName.of("example.com.");
    private static final int IN = 1;

    private QueryHandler handler;

    @BeforeEach
    void setUp() {
        Zone.Builder b = Zone.builder(ORIGIN)
                .add(soa())
                .add(new DnsRecord(ORIGIN, DnsRecordType.NS, IN, 3600,
                        RData.nameRdata(DnsName.of("ns1.example.com."))))
                .add(new DnsRecord(DnsName.of("ns1.example.com."), DnsRecordType.A, IN, 300,
                        RData.aRdata("192.0.2.1")))
                .add(new DnsRecord(DnsName.of("www.example.com."), DnsRecordType.A, IN, 123,
                        RData.aRdata("192.0.2.10")))
                .add(new DnsRecord(DnsName.of("www.example.com."), DnsRecordType.A, IN, 123,
                        RData.aRdata("192.0.2.11")))
                .add(new DnsRecord(DnsName.of("www.example.com."), DnsRecordType.TXT, IN, 50,
                        RData.txtRdata("web")))
                .add(new DnsRecord(DnsName.of("alias.example.com."), DnsRecordType.CNAME, IN, 300,
                        RData.nameRdata(DnsName.of("www.example.com."))))
                .add(new DnsRecord(DnsName.of("sub.example.com."), DnsRecordType.NS, IN, 3600,
                        RData.nameRdata(DnsName.of("ns.sub.example.com."))))
                .add(new DnsRecord(DnsName.of("ns.sub.example.com."), DnsRecordType.A, IN, 3600,
                        RData.aRdata("192.0.2.99")))
                .add(new DnsRecord(DnsName.of("weird.example.com."), 99, IN, 60,
                        new byte[]{1, 2, 3, 4}));
        ZoneStore store = new ZoneStore();
        store.replace(b.build());
        handler = new QueryHandler(store);
    }

    private static DnsRecord soa() {
        return new DnsRecord(ORIGIN, DnsRecordType.SOA, IN, 3600,
                RData.soaRdata(DnsName.of("ns1.example.com."), DnsName.of("hostmaster.example.com."),
                        2024010100L, 7200, 3600, 1209600, 60));
    }

    private DnsMessage query(String name, int type) {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(1);
        q.getHeader().setRd(true);
        q.getQuestions().add(new DnsQuestion(DnsName.of(name), type, IN));
        return q;
    }

    @Test
    void answersAQueryAuthoritativelyWithAllRecords() {
        DnsMessage resp = handler.handle(query("www.example.com.", DnsRecordType.A));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertTrue(resp.getHeader().isAa(), "response must be authoritative");
        assertEquals(2, resp.getAnswers().size());
        assertEquals(DnsRecordType.A, resp.getAnswers().get(0).getType());
        assertEquals(123L, resp.getAnswers().get(0).getTtl());
    }

    @Test
    void returnsNoerrorEmptyForExistingNameMissingType() {
        DnsMessage resp = handler.handle(query("www.example.com.", DnsRecordType.AAAA));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertTrue(resp.getAnswers().isEmpty(), "answer section must be empty for NODATA");
        assertEquals(1, resp.getAuthorities().size());
        assertEquals(DnsRecordType.SOA, resp.getAuthorities().get(0).getType());
        assertEquals(60L, resp.getAuthorities().get(0).getTtl(),
                "negative SOA TTL must equal SOA minimum");
        assertTrue(resp.getHeader().isAa());
    }

    @Test
    void returnsNxdomainWithSoaForMissingName() {
        DnsMessage resp = handler.handle(query("nope.example.com.", DnsRecordType.A));
        assertEquals(RCode.NXDOMAIN, resp.getHeader().getRcode());
        assertTrue(resp.getAnswers().isEmpty());
        assertEquals(1, resp.getAuthorities().size());
        assertEquals(DnsRecordType.SOA, resp.getAuthorities().get(0).getType());
        assertEquals(60L, resp.getAuthorities().get(0).getTtl());
    }

    @Test
    void chasesCnameAndAnswersAtTarget() {
        DnsMessage resp = handler.handle(query("alias.example.com.", DnsRecordType.A));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertEquals(3, resp.getAnswers().size(), "CNAME + 2 A records expected");
        assertEquals(DnsRecordType.CNAME, resp.getAnswers().get(0).getType());
        assertEquals(DnsName.of("www.example.com."),
                RData.nameFromRdata(resp.getAnswers().get(0).getRdata()));
        assertEquals(DnsRecordType.A, resp.getAnswers().get(1).getType());
    }

    @Test
    void returnsCnameOnlyForTypeAtTargetMissing() {
        // CNAME target (www) exists but has no AAAA.
        DnsMessage resp = handler.handle(query("alias.example.com.", DnsRecordType.AAAA));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertEquals(1, resp.getAnswers().size());
        assertEquals(DnsRecordType.CNAME, resp.getAnswers().get(0).getType());
        assertEquals(DnsRecordType.SOA, resp.getAuthorities().get(0).getType());
    }

    @Test
    void returnsDelegationWithoutAaAndWithGlue() {
        DnsMessage resp = handler.handle(query("host.sub.example.com.", DnsRecordType.A));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertFalse(resp.getHeader().isAa(), "referral must not be authoritative");
        assertTrue(resp.getAnswers().isEmpty());
        assertEquals(1, resp.getAuthorities().size());
        assertEquals(DnsRecordType.NS, resp.getAuthorities().get(0).getType());
        assertEquals(1, resp.getAdditionals().size());
        assertEquals(DnsRecordType.A, resp.getAdditionals().get(0).getType());
        assertEquals("192.0.2.99", RData.toText(DnsRecordType.A,
                resp.getAdditionals().get(0).getRdata()));
    }

    @Test
    void unknownRecordTypeDoesNotBreakResponses() {
        DnsMessage resp = handler.handle(query("weird.example.com.", DnsRecordType.A));
        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertTrue(resp.getAnswers().isEmpty());
        assertEquals(1, resp.getAuthorities().size(), "NODATA still carries SOA");
        assertEquals(DnsRecordType.SOA, resp.getAuthorities().get(0).getType());
    }

    @Test
    void copiesQuestionAndIdAndRd() {
        DnsMessage resp = handler.handle(query("www.example.com.", DnsRecordType.A));
        assertEquals(1, resp.getHeader().getId());
        assertEquals(1, resp.getQuestions().size());
        assertEquals(DnsName.of("www.example.com."), resp.getQuestions().get(0).name());
        assertTrue(resp.getHeader().isRd());
        assertTrue(resp.getHeader().isRa());
    }
}
