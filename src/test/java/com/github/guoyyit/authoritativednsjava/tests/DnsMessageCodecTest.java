package com.github.guoyyit.authoritativednsjava.tests;

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

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DnsMessageCodecTest {

    @Test
    void queryRoundTrip() throws Exception {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(0x1234);
        q.getHeader().setRd(true);
        q.getQuestions().add(new DnsQuestion(DnsName.of("www.example.com."), DnsRecordType.A, 1));

        DnsMessage decoded = DnsMessageCodec.decode(DnsMessageCodec.encode(q));

        assertEquals(0x1234, decoded.getHeader().getId());
        assertTrue(decoded.getHeader().isRd());
        assertEquals(1, decoded.getQuestions().size());
        DnsQuestion question = decoded.getQuestions().get(0);
        assertEquals(DnsName.of("www.example.com."), question.name());
        assertEquals(DnsRecordType.A, question.type());
        assertEquals(1, question.qclass());
    }

    @Test
    void responseWithAllRecordTypesRoundTrip() throws Exception {
        DnsMessage resp = new DnsMessage();
        resp.getHeader().setId(7);
        resp.getHeader().setQr(true);
        resp.getHeader().setAa(true);
        resp.getQuestions().add(new DnsQuestion(DnsName.of("example.com."), DnsRecordType.ANY, 1));
        resp.getAnswers().add(new DnsRecord(DnsName.of("example.com."), DnsRecordType.A, 1, 300,
                RData.aRdata("192.0.2.1")));
        resp.getAnswers().add(new DnsRecord(DnsName.of("example.com."), DnsRecordType.AAAA, 1, 300,
                RData.aaaaRdata("2001:db8::1")));
        resp.getAnswers().add(new DnsRecord(DnsName.of("alias.example.com."), DnsRecordType.CNAME, 1, 300,
                RData.nameRdata(DnsName.of("example.com."))));
        resp.getAnswers().add(new DnsRecord(DnsName.of("example.com."), DnsRecordType.NS, 1, 300,
                RData.nameRdata(DnsName.of("ns1.example.com."))));
        resp.getAnswers().add(new DnsRecord(DnsName.of("example.com."), DnsRecordType.SOA, 1, 300,
                RData.soaRdata(DnsName.of("ns1.example.com."), DnsName.of("hostmaster.example.com."),
                        2024010100L, 7200, 3600, 1209600, 60)));
        resp.getAnswers().add(new DnsRecord(DnsName.of("example.com."), DnsRecordType.MX, 1, 300,
                RData.mxRdata(10, DnsName.of("mail.example.com."))));
        resp.getAnswers().add(new DnsRecord(DnsName.of("example.com."), DnsRecordType.TXT, 1, 300,
                RData.txtRdata("v=spf1 -all")));

        DnsMessage decoded = DnsMessageCodec.decode(DnsMessageCodec.encode(resp));

        assertEquals(7, decoded.getAnswers().size());
        for (int i = 0; i < 7; i++) {
            assertEquals(resp.getAnswers().get(i), decoded.getAnswers().get(i),
                    "record " + i + " mismatch");
        }
    }

    @Test
    void decodesManuallyCompressedMessage() throws Exception {
        // Hand-built response where the answer name is a compression pointer
        // back to the question name at offset 12.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU16(out, 0xBEEF);            // id
        writeU16(out, 0x8580);            // qr aa rd ra
        writeU16(out, 1);                 // qd
        writeU16(out, 1);                 // an
        writeU16(out, 0);
        writeU16(out, 0);
        writeName(out, "www.example.com.");
        writeU16(out, DnsRecordType.A);
        writeU16(out, 1);
        writeU16(out, 0xC00C);            // pointer to offset 12
        writeU16(out, DnsRecordType.A);
        writeU16(out, 1);
        writeU32(out, 300);
        writeU16(out, 4);
        out.write(new byte[]{10, 0, 0, 1});

        DnsMessage decoded = DnsMessageCodec.decode(out.toByteArray());
        assertEquals(0xBEEF, decoded.getHeader().getId());
        assertEquals(1, decoded.getAnswers().size());
        DnsRecord a = decoded.getAnswers().get(0);
        assertEquals(DnsName.of("www.example.com."), a.getName());
        assertArrayEquals(new byte[]{10, 0, 0, 1}, a.getRdata());
    }

    @Test
    void decodesCompressedNameInsideRdata() throws Exception {
        // CNAME answer whose RDATA target is a pointer into the question name.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU16(out, 1);
        writeU16(out, 0x8580);
        writeU16(out, 1);
        writeU16(out, 1);
        writeU16(out, 0);
        writeU16(out, 0);
        writeName(out, "alias.example.com.");   // offset 12
        writeU16(out, DnsRecordType.CNAME);
        writeU16(out, 1);
        writeU16(out, 0xC012);                  // "example.com." starts at offset 18
        writeU16(out, DnsRecordType.CNAME);
        writeU16(out, 1);
        writeU32(out, 60);
        writeU16(out, 2);                       // rdlength = 2 (just the pointer)
        writeU16(out, 0xC012);                  // pointer to "example.com." at offset 18

        DnsMessage decoded = DnsMessageCodec.decode(out.toByteArray());
        DnsRecord cname = decoded.getAnswers().get(0);
        // RDATA is normalized to uncompressed wire form.
        assertEquals(DnsName.of("example.com."), RData.nameFromRdata(cname.getRdata()));
    }

    @Test
    void unknownRecordTypeSurvivesRoundTrip() throws Exception {
        DnsMessage resp = new DnsMessage();
        resp.getHeader().setQr(true);
        resp.getQuestions().add(new DnsQuestion(DnsName.of("example.com."), DnsRecordType.A, 1));
        byte[] exotic = {0x01, 0x02, 0x03, 0x04, 0x05};
        resp.getAnswers().add(new DnsRecord(DnsName.of("example.com."), 99, 1, 60, exotic));
        resp.getAnswers().add(new DnsRecord(DnsName.of("example.com."), DnsRecordType.A, 1, 60,
                RData.aRdata("192.0.2.9")));

        DnsMessage decoded = DnsMessageCodec.decode(DnsMessageCodec.encode(resp));

        assertEquals(2, decoded.getAnswers().size());
        assertEquals(99, decoded.getAnswers().get(0).getType());
        assertArrayEquals(exotic, decoded.getAnswers().get(0).getRdata());
        assertEquals(DnsRecordType.A, decoded.getAnswers().get(1).getType());
    }

    @Test
    void rejectsTruncatedMessage() {
        byte[] garbage = {0, 1, 0, 0, 0, 1}; // shorter than a header
        assertThrows(DnsParseException.class, () -> DnsMessageCodec.decode(garbage));
    }

    @Test
    void rejectsCompressionPointerLoop() {
        // Name at offset 12 is a pointer to itself.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU16(out, 1);
        writeU16(out, 0x0100);
        writeU16(out, 1);
        writeU16(out, 0);
        writeU16(out, 0);
        writeU16(out, 0);
        writeU16(out, 0xC00C); // pointer to offset 12 (itself)
        writeU16(out, DnsRecordType.A);
        writeU16(out, 1);
        assertThrows(DnsParseException.class, () -> DnsMessageCodec.decode(out.toByteArray()));
    }

    @Test
    void rejectsPointerOutOfRange() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeU16(out, 1);
        writeU16(out, 0x0100);
        writeU16(out, 1);
        writeU16(out, 0);
        writeU16(out, 0);
        writeU16(out, 0);
        writeU16(out, 0x3FFF); // pointer far beyond message end
        writeU16(out, DnsRecordType.A);
        writeU16(out, 1);
        assertThrows(DnsParseException.class, () -> DnsMessageCodec.decode(out.toByteArray()));
    }

    @Test
    void headerFlagsRoundTrip() throws Exception {
        DnsMessage m = new DnsMessage();
        m.getHeader().setId(42);
        m.getHeader().setQr(true);
        m.getHeader().setAa(true);
        m.getHeader().setTc(true);
        m.getHeader().setRd(true);
        m.getHeader().setRa(true);
        m.getHeader().setRcode(RCode.NXDOMAIN);

        DnsMessage decoded = DnsMessageCodec.decode(DnsMessageCodec.encode(m));
        assertTrue(decoded.getHeader().isQr());
        assertTrue(decoded.getHeader().isAa());
        assertTrue(decoded.getHeader().isTc());
        assertTrue(decoded.getHeader().isRd());
        assertTrue(decoded.getHeader().isRa());
        assertEquals(RCode.NXDOMAIN, decoded.getHeader().getRcode());
    }

    private static void writeU16(ByteArrayOutputStream out, int v) {
        out.write((v >>> 8) & 0xFF);
        out.write(v & 0xFF);
    }

    private static void writeU32(ByteArrayOutputStream out, long v) {
        out.write((int) (v >>> 24) & 0xFF);
        out.write((int) (v >>> 16) & 0xFF);
        out.write((int) (v >>> 8) & 0xFF);
        out.write((int) v & 0xFF);
    }

    private static void writeName(ByteArrayOutputStream out, String dotted) {
        String s = dotted.endsWith(".") ? dotted.substring(0, dotted.length() - 1) : dotted;
        Arrays.stream(s.split("\\.")).forEach(label -> {
            out.write(label.length());
            for (char c : label.toCharArray()) {
                out.write((byte) c);
            }
        });
        out.write(0);
    }
}
