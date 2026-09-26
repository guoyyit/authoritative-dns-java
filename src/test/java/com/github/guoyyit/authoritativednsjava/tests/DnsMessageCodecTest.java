package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsHeader;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessageCodec;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsParseException;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RCode;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Wire parsing/framing: compression, multiple records, unknown types. */
class DnsMessageCodecTest {

    @Test
    void queryRoundTrip() throws Exception {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(0x1234);
        q.getHeader().setRd(true);
        q.getQuestions().add(new DnsQuestion(DnsName.of("www.example.com."),
                DnsRecordType.A, 1));

        byte[] wire = DnsMessageCodec.encode(q);
        DnsMessage decoded = DnsMessageCodec.decode(wire);

        assertEquals(0x1234, decoded.getHeader().getId());
        assertTrue(decoded.getHeader().isRd());
        assertEquals(1, decoded.getQuestions().size());
        assertEquals(DnsName.of("www.example.com."), decoded.getQuestions().get(0).name());
        assertEquals(DnsRecordType.A, decoded.getQuestions().get(0).type());
    }

    @Test
    void responseWithCompressedNamesDecodesAllRecords() throws Exception {
        DnsMessage m = new DnsMessage();
        DnsHeader h = m.getHeader();
        h.setId(7);
        h.setQr(true);
        h.setAa(true);
        DnsName name = DnsName.of("www.example.com.");
        m.getQuestions().add(new DnsQuestion(name, DnsRecordType.A, 1));
        m.getAnswers().add(new DnsRecord(name, DnsRecordType.A, 1, 300,
                RData.aRdata("192.0.2.5")));
        m.getAnswers().add(new DnsRecord(name, DnsRecordType.A, 1, 300,
                RData.aRdata("192.0.2.6")));
        m.getAuthorities().add(new DnsRecord(DnsName.of("example.com."),
                DnsRecordType.NS, 1, 3600,
                RData.nameRdata(DnsName.of("ns.example.com."))));
        m.getAdditionals().add(new DnsRecord(DnsName.of("ns.example.com."),
                DnsRecordType.AAAA, 1, 300, RData.aaaaRdata("2001:db8::1")));

        byte[] wire = DnsMessageCodec.encode(m);
        DnsMessage decoded = DnsMessageCodec.decode(wire);

        assertEquals(RCode.NOERROR, decoded.getHeader().getRcode());
        assertTrue(decoded.getHeader().isAa());
        assertEquals(2, decoded.getAnswers().size());
        assertEquals(DnsRecordType.A, decoded.getAnswers().get(0).getType());
        assertArrayEquals(RData.aRdata("192.0.2.5"), decoded.getAnswers().get(0).getRdata());
        assertEquals(name, decoded.getAnswers().get(1).getName());
        assertEquals(DnsName.of("ns.example.com."),
                RData.nameFromRdata(decoded.getAuthorities().get(0).getRdata()));
        assertArrayEquals(RData.aaaaRdata("2001:db8::1"),
                decoded.getAdditionals().get(0).getRdata());
        // Encoder must actually have emitted at least one compression pointer.
        boolean hasPointer = false;
        for (byte b : wire) {
            if ((b & 0xC0) == 0xC0) {
                hasPointer = true;
                break;
            }
        }
        assertTrue(hasPointer, "expected compressed names on the wire");
    }

    @Test
    void unknownRecordTypeIsKeptVerbatimAndDoesNotFail() throws Exception {
        // TYPE99 (SPF-like, but deliberately unknown to this implementation) RDATA.
        byte[] rawRdata = new byte[]{0x01, 0x02, 0x03};
        DnsMessage m = new DnsMessage();
        m.getHeader().setId(9);
        m.getHeader().setQr(true);
        m.getQuestions().add(new DnsQuestion(DnsName.of("x.test."), 99, 1));
        m.getAnswers().add(new DnsRecord(DnsName.of("x.test."), 99, 1, 60, rawRdata));

        byte[] wire = DnsMessageCodec.encode(m);
        DnsMessage decoded = DnsMessageCodec.decode(wire);

        assertEquals(1, decoded.getAnswers().size());
        assertEquals(99, decoded.getAnswers().get(0).getType());
        assertArrayEquals(rawRdata, decoded.getAnswers().get(0).getRdata());
    }

    @Test
    void txtSoaMxCnameRoundTrips() throws Exception {
        DnsMessage m = new DnsMessage();
        m.getHeader().setQr(true);
        DnsName origin = DnsName.of("example.com.");
        m.getQuestions().add(new DnsQuestion(origin, DnsRecordType.SOA, 1));
        m.getAnswers().add(new DnsRecord(origin, DnsRecordType.SOA, 1, 3600,
                RData.soaRdata(DnsName.of("ns.example.com."), DnsName.of("rm.example.com."),
                        42, 7200, 3600, 1_209_600, 60)));
        m.getAnswers().add(new DnsRecord(DnsName.of("mail.example.com."),
                DnsRecordType.MX, 1, 300,
                RData.mxRdata(10, DnsName.of("mx.example.com."))));
        m.getAnswers().add(new DnsRecord(DnsName.of("alias.example.com."),
                DnsRecordType.CNAME, 1, 300,
                RData.nameRdata(DnsName.of("target.example.com."))));
        m.getAnswers().add(new DnsRecord(DnsName.of("t.example.com."),
                DnsRecordType.TXT, 1, 300, RData.txtRdata("v=spf1 -all")));

        DnsMessage decoded = DnsMessageCodec.decode(DnsMessageCodec.encode(m));
        assertEquals(4, decoded.getAnswers().size());
        String soaText = RData.toText(DnsRecordType.SOA, decoded.getAnswers().get(0).getRdata());
        assertTrue(soaText.contains("42"));
        assertTrue(RData.toText(DnsRecordType.MX, decoded.getAnswers().get(1).getRdata())
                .startsWith("10 "));
        assertEquals(DnsName.of("target.example.com."),
                RData.nameFromRdata(decoded.getAnswers().get(2).getRdata()));
        assertEquals("\"v=spf1 -all\"",
                RData.toText(DnsRecordType.TXT, decoded.getAnswers().get(3).getRdata()));
    }

    @Test
    void rejectsTooShortMessage() {
        assertThrows(DnsParseException.class, () -> DnsMessageCodec.decode(new byte[11]));
    }

    @Test
    void rejectsCompressionPointerLoop() {
        // Header + question name pointer to itself at offset 12.
        byte[] wire = new byte[17];
        wire[12] = (byte) 0xC0;
        wire[13] = 0x0C;
        assertThrows(DnsParseException.class, () -> DnsMessageCodec.decode(wire));
    }

    @Test
    void headerFlagsEncoded() {
        DnsMessage m = new DnsMessage();
        DnsHeader h = m.getHeader();
        h.setId(1);
        h.setQr(true);
        h.setAa(true);
        h.setTc(true);
        h.setRa(true);
        h.setRcode(RCode.NXDOMAIN);
        byte[] wire = DnsMessageCodec.encode(m);
        int flags = ((wire[2] & 0xFF) << 8) | (wire[3] & 0xFF);
        assertEquals(0x8000 | 0x0400 | 0x0200 | 0x0080 | 3, flags);
    }

    @Test
    void longTxtIsChunkedInto255ByteStrings() {
        String s = "a".repeat(300);
        byte[] rdata = RData.txtRdata(s);
        // 255 chunk + 45 chunk => 2 length bytes + 300 payload bytes
        assertEquals(302, rdata.length);
        assertEquals(255, rdata[0] & 0xFF);
        assertEquals(45, rdata[256] & 0xFF);
        // sanity on charset handling
        byte[] ascii = "abc".getBytes(StandardCharsets.US_ASCII);
        assertEquals(3, ascii.length);
    }
}
