package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessageCodec;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.server.QueryHandler;
import com.github.guoyyit.authoritativednsjava.dns.server.TcpDnsServer;
import com.github.guoyyit.authoritativednsjava.dns.server.UdpDnsServer;
import com.github.guoyyit.authoritativednsjava.dns.server.ZoneTransferHandler;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TransportTruncationTest {

    private static final DnsName ORIGIN = DnsName.of("big.example.com.");
    private static final DnsName WWW = DnsName.of("www.big.example.com.");
    private static final int IN = 1;
    private static final int MANY = 80;

    private UdpDnsServer udp;
    private TcpDnsServer tcp;
    private int udpPort;
    private int tcpPort;

    @BeforeEach
    void startServers() throws Exception {
        udpPort = freeUdpPort();
        tcpPort = freeTcpPort();
        DnsServerConfig config = new DnsServerConfig();
        config.setListenAddress("127.0.0.1");
        config.setUdpPort(udpPort);
        config.setTcpPort(tcpPort);
        config.setUdpMaxPayload(512);
        config.setTransferKey("transfer-secret");

        Zone.Builder b = Zone.builder(ORIGIN)
                .add(new DnsRecord(ORIGIN, DnsRecordType.SOA, IN, 3600,
                        RData.soaRdata(DnsName.of("ns1.big.example.com."),
                                DnsName.of("hm.big.example.com."), 1, 7200, 3600, 1209600, 60)));
        for (int i = 1; i <= MANY; i++) {
            b.add(new DnsRecord(WWW, DnsRecordType.A, IN, 300,
                    new byte[]{10, 1, (byte) (i >> 8), (byte) i}));
        }
        ZoneStore store = new ZoneStore();
        store.replace(b.build());
        QueryHandler queryHandler = new QueryHandler(store);
        ZoneTransferHandler transferHandler =
                new ZoneTransferHandler(config, store, new AuditLog());
        udp = new UdpDnsServer(config, queryHandler);
        tcp = new TcpDnsServer(config, queryHandler, transferHandler);
        udp.start();
        tcp.start();
    }

    @AfterEach
    void stopServers() {
        udp.stop();
        tcp.stop();
    }

    private static int freeTcpPort() throws Exception {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    private static int freeUdpPort() throws Exception {
        try (DatagramSocket d = new DatagramSocket()) {
            return d.getLocalPort();
        }
    }

    private static byte[] query(int id, String name, int type) {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(id);
        q.getHeader().setRd(true);
        q.getQuestions().add(new DnsQuestion(DnsName.of(name), type, IN));
        return DnsMessageCodec.encode(q);
    }

    private static byte[] udpRoundTrip(byte[] request, int port) throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000);
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            socket.send(new DatagramPacket(request, request.length, loopback, port));
            byte[] buf = new byte[65535];
            DatagramPacket response = new DatagramPacket(buf, buf.length);
            socket.receive(response);
            byte[] copy = new byte[response.getLength()];
            System.arraycopy(buf, 0, copy, 0, response.getLength());
            return copy;
        }
    }

    private static byte[] tcpRoundTrip(byte[] request, int port) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());
            out.writeShort(request.length);
            out.write(request);
            int length = in.readUnsignedShort();
            byte[] response = new byte[length];
            in.readFully(response);
            return response;
        }
    }

    @Test
    void udpTruncatesWithTcBit() throws Exception {
        byte[] raw = udpRoundTrip(query(1, "www.big.example.com.", DnsRecordType.ANY), udpPort);
        assertTrue(raw.length <= 512, "UDP response must fit the payload limit, was " + raw.length);
        DnsMessage resp = DnsMessageCodec.decode(raw);
        assertTrue(resp.getHeader().isTc(), "TC bit must be set on truncation");
        assertEquals(0, resp.getAnswers().size());
    }

    @Test
    void tcpRetryReturnsFullResponse() throws Exception {
        byte[] raw = tcpRoundTrip(query(1, "www.big.example.com.", DnsRecordType.ANY), tcpPort);
        assertTrue(raw.length > 512, "TCP response should be the full (large) message");
        DnsMessage resp = DnsMessageCodec.decode(raw);
        assertFalse(resp.getHeader().isTc(), "TCP responses are never truncated");
        assertEquals(MANY, resp.getAnswers().size());
    }

    @Test
    void smallUdpResponseIsNotTruncated() throws Exception {
        byte[] raw = udpRoundTrip(query(2, "www.big.example.com.", DnsRecordType.AAAA), udpPort);
        assertTrue(raw.length <= 512);
        DnsMessage resp = DnsMessageCodec.decode(raw);
        assertFalse(resp.getHeader().isTc());
        assertTrue(resp.getAnswers().isEmpty()); // NODATA
        assertEquals(1, resp.getAuthorities().size()); // SOA present
    }

    @Test
    void tcpFramingHandlesTwoQueriesOnOneConnection() throws Exception {
        try (Socket socket = new Socket("127.0.0.1", tcpPort)) {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());
            byte[] q1 = query(10, "www.big.example.com.", DnsRecordType.A);
            byte[] q2 = query(11, "www.big.example.com.", DnsRecordType.A);
            out.writeShort(q1.length);
            out.write(q1);
            out.writeShort(q2.length);
            out.write(q2);
            for (int expectedId : new int[]{10, 11}) {
                int length = in.readUnsignedShort();
                byte[] response = new byte[length];
                in.readFully(response);
                DnsMessage decoded = DnsMessageCodec.decode(response);
                assertEquals(expectedId, decoded.getHeader().getId());
                assertEquals(MANY, decoded.getAnswers().size());
            }
        }
    }

    @Test
    void malformedUdpDatagramGetsFormerror() throws Exception {
        byte[] raw = udpRoundTrip(new byte[]{0, 1, 2}, udpPort);
        DnsMessage resp = DnsMessageCodec.decode(raw);
        assertEquals(com.github.guoyyit.authoritativednsjava.dns.protocol.RCode.FORMERR,
                resp.getHeader().getRcode());
    }
}
