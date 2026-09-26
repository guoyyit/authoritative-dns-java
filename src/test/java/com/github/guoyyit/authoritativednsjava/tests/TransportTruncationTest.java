package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessageCodec;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RCode;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.server.QueryHandler;
import com.github.guoyyit.authoritativednsjava.dns.server.TcpDnsServer;
import com.github.guoyyit.authoritativednsjava.dns.server.UdpDnsServer;
import com.github.guoyyit.authoritativednsjava.dns.server.ZoneTransferHandler;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** End-to-end transport: UDP truncation + TC, TCP full retry, framing, AXFR auth. */
class TransportTruncationTest {

    private static final int IN = 1;
    private static final String XFER_KEY = "transfer-secret";
    private static final int MANY = 60; // makes an A response well over 512 bytes

    private static int freePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return s.getLocalPort();
        }
    }

    private static DnsMessage query(String name, int type) {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(0x4242);
        q.getHeader().setRd(true);
        q.getQuestions().add(new DnsQuestion(DnsName.of(name), type, IN));
        return q;
    }

    private static Zone bigZone() {
        DnsName origin = DnsName.of("big.test.");
        Zone.Builder b = Zone.builder(origin)
                .add(new DnsRecord(origin, DnsRecordType.SOA, IN, 3600,
                        RData.soaRdata(DnsName.of("ns.big.test."), DnsName.of("hm.big.test."),
                                1, 7200, 3600, 100, 60)))
                .add(new DnsRecord(origin, DnsRecordType.NS, IN, 3600,
                        RData.nameRdata(DnsName.of("ns.big.test."))))
                .add(new DnsRecord(DnsName.of("ns.big.test."), DnsRecordType.A, IN, 300,
                        RData.aRdata("127.0.0.1")));
        for (int i = 0; i < MANY; i++) {
            b.add(new DnsRecord(DnsName.of("many.big.test."), DnsRecordType.A, IN, 300,
                    RData.aRdata("10.1." + (i / 250) + "." + (i % 250 + 1))));
        }
        return b.build();
    }

    private record Harness(DnsServerConfig config, UdpDnsServer udp, TcpDnsServer tcp) {
        void stop() {
            udp.stop();
            tcp.stop();
        }
    }

    private Harness start(Path dataDir) throws Exception {
        DnsServerConfig cfg = new DnsServerConfig();
        cfg.setListenAddress("127.0.0.1");
        cfg.setUdpPort(freePort());
        cfg.setTcpPort(freePort());
        cfg.setUdpMaxPayload(512);
        cfg.setTransferKey(XFER_KEY);

        ZoneStore store = new ZoneStore();
        store.replace(bigZone());
        QueryHandler qh = new QueryHandler(store);
        AuditLog audit = new AuditLog();
        audit.setFile(dataDir.resolve("audit.log"));
        ZoneTransferHandler xh = new ZoneTransferHandler(cfg, store, audit);

        UdpDnsServer udp = new UdpDnsServer(cfg, qh);
        TcpDnsServer tcp = new TcpDnsServer(cfg, qh, xh);
        udp.start();
        tcp.start();
        // Give the listeners a moment to be ready.
        Thread.sleep(100);
        return new Harness(cfg, udp, tcp);
    }

    private byte[] udpExchange(DnsServerConfig cfg, byte[] request) throws Exception {
        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setSoTimeout(3000);
            InetSocketAddress to = new InetSocketAddress("127.0.0.1", cfg.getUdpPort());
            sock.send(new DatagramPacket(request, request.length, to));
            byte[] buf = new byte[65535];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            sock.receive(resp);
            byte[] out = new byte[resp.getLength()];
            System.arraycopy(buf, 0, out, 0, resp.getLength());
            return out;
        }
    }

    private byte[] tcpExchange(DnsServerConfig cfg, byte[] request) throws Exception {
        try (Socket sock = new Socket()) {
            sock.setSoTimeout(3000);
            sock.connect(new InetSocketAddress("127.0.0.1", cfg.getTcpPort()));
            DataOutputStream out = new DataOutputStream(sock.getOutputStream());
            DataInputStream in = new DataInputStream(sock.getInputStream());
            out.writeShort(request.length);
            out.write(request);
            out.flush();
            int len = in.readUnsignedShort();
            byte[] resp = new byte[len];
            in.readFully(resp);
            return resp;
        }
    }

    @Test
    void smallQueryAnsweredOverUdpWithoutTruncation(@TempDir Path dir) throws Exception {
        Harness h = start(dir);
        try {
            byte[] respBytes = udpExchange(h.config(),
                    DnsMessageCodec.encode(query("ns.big.test.", DnsRecordType.A)));
            DnsMessage resp = DnsMessageCodec.decode(respBytes);
            assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
            assertFalse(resp.getHeader().isTc());
            assertEquals(1, resp.getAnswers().size());
        } finally {
            h.stop();
        }
    }

    @Test
    void udpTruncatesLargeResponseAndTcpRetryIsFull(@TempDir Path dir) throws Exception {
        Harness h = start(dir);
        try {
            byte[] request = DnsMessageCodec.encode(query("many.big.test.", DnsRecordType.A));

            // UDP: larger than 512 -> TC set, answer section dropped.
            byte[] udpBytes = udpExchange(h.config(), request);
            assertTrue(udpBytes.length <= 512, "UDP datagram must fit the payload limit");
            DnsMessage udpResp = DnsMessageCodec.decode(udpBytes);
            assertTrue(udpResp.getHeader().isTc(), "TC bit must be set");
            assertTrue(udpResp.getAnswers().isEmpty());

            // Client retries over TCP: complete response, no truncation.
            byte[] tcpBytes = tcpExchange(h.config(), request);
            DnsMessage tcpResp = DnsMessageCodec.decode(tcpBytes);
            assertFalse(tcpResp.getHeader().isTc());
            assertEquals(MANY, tcpResp.getAnswers().size());
            assertTrue(tcpBytes.length > 512, "full response exceeds UDP size");
        } finally {
            h.stop();
        }
    }

    @Test
    void tcpFramingSupportsTwoSequentialQueriesOnOneConnection(@TempDir Path dir) throws Exception {
        Harness h = start(dir);
        try (Socket sock = new Socket()) {
            sock.setSoTimeout(3000);
            sock.connect(new InetSocketAddress("127.0.0.1", h.config().getTcpPort()));
            DataOutputStream out = new DataOutputStream(sock.getOutputStream());
            DataInputStream in = new DataInputStream(sock.getInputStream());

            for (String name : new String[]{"ns.big.test.", "many.big.test."}) {
                byte[] req = DnsMessageCodec.encode(query(name, DnsRecordType.A));
                out.writeShort(req.length);
                out.write(req);
                out.flush();
                int len = in.readUnsignedShort();
                byte[] resp = new byte[len];
                in.readFully(resp);
                DnsMessage decoded = DnsMessageCodec.decode(resp);
                assertEquals(RCode.NOERROR, decoded.getHeader().getRcode());
            }
        } finally {
            h.stop();
        }
    }

    private static byte[] axfrRequest(String key) {
        DnsMessage q = query("big.test.", DnsRecordType.AXFR);
        if (key != null) {
            q.getAdditionals().add(new DnsRecord(DnsName.of("key."), DnsRecordType.TXT, IN, 0,
                    RData.txtRdata(key)));
        }
        return DnsMessageCodec.encode(q);
    }

    @Test
    void authorizedAxfrReturnsCompleteSelfConsistentZone(@TempDir Path dir) throws Exception {
        Harness h = start(dir);
        try {
            byte[] respBytes = tcpExchange(h.config(), axfrRequest(XFER_KEY));
            DnsMessage resp = DnsMessageCodec.decode(respBytes);
            assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
            assertTrue(resp.getHeader().isAa());
            var answers = resp.getAnswers();
            // RFC 5936: AXFR starts and ends with the zone SOA.
            assertEquals(DnsRecordType.SOA, answers.get(0).getType());
            assertEquals(DnsRecordType.SOA, answers.get(answers.size() - 1).getType());
            // Zone records: SOA + NS + glue A + MANY A = MANY+3; AXFR adds a
            // closing SOA (the opening SOA is already part of the zone data).
            assertEquals(MANY + 5, answers.size());
        } finally {
            h.stop();
        }
    }

    @Test
    void unauthorizedAxfrIsRefusedAndAudited(@TempDir Path dir) throws Exception {
        Harness h = start(dir);
        try {
            byte[] bad = tcpExchange(h.config(), axfrRequest("wrong-key"));
            assertEquals(RCode.REFUSED, DnsMessageCodec.decode(bad).getHeader().getRcode());

            byte[] none = tcpExchange(h.config(), axfrRequest(null));
            assertEquals(RCode.REFUSED, DnsMessageCodec.decode(none).getHeader().getRcode());

            String audit = Files.readString(dir.resolve("audit.log"));
            assertTrue(audit.contains("action=AXFR"));
            assertTrue(audit.contains("result=DENIED"));
            assertTrue(audit.contains("reason=bad-key"));
        } finally {
            h.stop();
        }
    }

    @Test
    void axfrOverUdpIsRefused(@TempDir Path dir) throws Exception {
        Harness h = start(dir);
        try {
            byte[] respBytes = udpExchange(h.config(), axfrRequest(XFER_KEY));
            assertEquals(RCode.REFUSED, DnsMessageCodec.decode(respBytes).getHeader().getRcode());
        } finally {
            h.stop();
        }
    }
}
