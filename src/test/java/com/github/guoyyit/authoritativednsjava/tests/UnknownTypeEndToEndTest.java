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
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerLifecycle;
import com.github.guoyyit.authoritativednsjava.dns.server.QueryHandler;
import com.github.guoyyit.authoritativednsjava.dns.server.TcpDnsServer;
import com.github.guoyyit.authoritativednsjava.dns.server.UdpDnsServer;
import com.github.guoyyit.authoritativednsjava.dns.server.ZoneTransferHandler;
import com.github.guoyyit.authoritativednsjava.dns.update.ZoneAdminController;
import com.github.guoyyit.authoritativednsjava.dns.update.ZoneUpdateService;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Unknown-type full chain: admin submit -> in-memory zone -> zone file ->
 * restart recovery -> UDP/TCP answers -> AXFR. The type code submitted as
 * TYPEnnn must appear verbatim at every stage (regression: TYPE99 was
 * silently rewritten to 9, TYPE9 broke zone reload).
 */
class UnknownTypeEndToEndTest {

    private static final int IN = 1;
    private static final String UPDATE_KEY = "update-secret";
    private static final String XFER_KEY = "transfer-secret";
    private static final DnsName ORIGIN = DnsName.of("e2e.test.");

    @TempDir
    Path dir;
    private Path zoneFile;
    private ZoneStore store;
    private MockMvc mvc;

    @BeforeEach
    void setUp() throws Exception {
        zoneFile = dir.resolve("zone.dat");
        DnsServerConfig cfg = new DnsServerConfig();
        cfg.setUpdateKey(UPDATE_KEY);
        cfg.setTransferKey(XFER_KEY);
        store = new ZoneStore();
        Zone seed = Zone.builder(ORIGIN)
                .add(new DnsRecord(ORIGIN, DnsRecordType.SOA, IN, 60,
                        RData.soaRdata(DnsName.of("ns.e2e.test."), DnsName.of("hm.e2e.test."),
                                1, 7200, 3600, 100, 60)))
                .build();
        ZonePersistence persistence = new ZonePersistence(zoneFile);
        persistence.save(seed);
        store.replace(seed);
        AuditLog audit = new AuditLog();
        audit.setFile(dir.resolve("audit.log"));
        mvc = MockMvcBuilders.standaloneSetup(
                new ZoneAdminController(new ZoneUpdateService(cfg, store, persistence, audit),
                        store))
                .build();
    }

    // ------------------------------------------------------------ helpers

    private static int freePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return s.getLocalPort();
        }
    }

    private void submitRecord(String name, String type, long ttl, String rdata, int expectStatus)
            throws Exception {
        // JSON-escape the RDATA text (generic \# form contains a backslash).
        String jsonRdata = rdata.replace("\\", "\\\\").replace("\"", "\\\"");
        String body = """
                {"add":[{"name":"%s","type":"%s","ttl":%d,"rdata":"%s"}],"remove":[]}
                """.formatted(name, type, ttl, jsonRdata);
        var request = post("/zones/records")
                .header("X-Update-Key", UPDATE_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body);
        if (expectStatus == 200) {
            mvc.perform(request).andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("updated"));
        } else {
            mvc.perform(request).andExpect(status().is(expectStatus))
                    .andExpect(jsonPath("$.error").exists());
        }
    }

    private record Harness(DnsServerConfig config, UdpDnsServer udp, TcpDnsServer tcp) {
        void stop() {
            udp.stop();
            tcp.stop();
        }
    }

    private Harness startServers(ZoneStore zoneStore) throws Exception {
        DnsServerConfig cfg = new DnsServerConfig();
        cfg.setListenAddress("127.0.0.1");
        cfg.setUdpPort(freePort());
        cfg.setTcpPort(freePort());
        cfg.setUdpMaxPayload(512);
        cfg.setTransferKey(XFER_KEY);
        QueryHandler qh = new QueryHandler(zoneStore);
        AuditLog audit = new AuditLog();
        audit.setFile(dir.resolve("audit.log"));
        UdpDnsServer udp = new UdpDnsServer(cfg, qh);
        TcpDnsServer tcp = new TcpDnsServer(cfg, qh, new ZoneTransferHandler(cfg, zoneStore, audit));
        udp.start();
        tcp.start();
        Thread.sleep(100);
        return new Harness(cfg, udp, tcp);
    }

    private static DnsMessage query(String name, int type) {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(0x4242);
        q.getQuestions().add(new DnsQuestion(DnsName.of(name), type, IN));
        return q;
    }

    private static byte[] udpExchange(int port, byte[] request) throws Exception {
        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setSoTimeout(3000);
            sock.send(new DatagramPacket(request, request.length,
                    new InetSocketAddress("127.0.0.1", port)));
            byte[] buf = new byte[65535];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            sock.receive(resp);
            byte[] out = new byte[resp.getLength()];
            System.arraycopy(buf, 0, out, 0, resp.getLength());
            return out;
        }
    }

    private static byte[] tcpExchange(int port, byte[] request) throws Exception {
        try (Socket sock = new Socket()) {
            sock.setSoTimeout(3000);
            sock.connect(new InetSocketAddress("127.0.0.1", port));
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

    private static byte[] axfrRequest() {
        DnsMessage q = query(ORIGIN.toString(), DnsRecordType.AXFR);
        q.getAdditionals().add(new DnsRecord(DnsName.of("key."), DnsRecordType.TXT, IN, 0,
                RData.txtRdata(XFER_KEY)));
        return DnsMessageCodec.encode(q);
    }

    private static void assertRecordExactly(DnsRecord r, DnsName owner, int type, long ttl,
                                            byte[] rdata) {
        assertEquals(owner, r.getName());
        assertEquals(type, r.getType());
        assertEquals(IN, r.getRrclass());
        assertEquals(ttl, r.getTtl());
        assertArrayEquals(rdata, r.getRdata());
    }

    // ------------------------------------------------------------ tests

    @Test
    void submittedType99KeepsExactCodeThroughFileQueryAndAxfr() throws Exception {
        byte[] rdata = {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE};
        submitRecord("u99.e2e.test.", "TYPE99", 300, "\\# 3 de ad be", 200);

        // In-memory zone holds the exact code.
        DnsRecord inMemory = store.current().orElseThrow()
                .lookup(DnsName.of("u99.e2e.test."), 99).get(0);
        assertRecordExactly(inMemory, DnsName.of("u99.e2e.test."), 99, 300, rdata);

        // The persisted file carries the full TYPE99 token.
        String persisted = Files.readString(zoneFile);
        assertTrue(persisted.contains("u99.e2e.test. 300 TYPE99 "),
                "zone file must contain the exact TYPE99 record:\n" + persisted);

        Harness h = startServers(store);
        try {
            // UDP answer carries the stored code.
            DnsMessage udpResp = DnsMessageCodec.decode(
                    udpExchange(h.config().getUdpPort(),
                            DnsMessageCodec.encode(query("u99.e2e.test.", 99))));
            assertEquals(RCode.NOERROR, udpResp.getHeader().getRcode());
            assertEquals(1, udpResp.getAnswers().size());
            assertRecordExactly(udpResp.getAnswers().get(0),
                    DnsName.of("u99.e2e.test."), 99, 300, rdata);

            // TCP answer carries the stored code.
            DnsMessage tcpResp = DnsMessageCodec.decode(
                    tcpExchange(h.config().getTcpPort(),
                            DnsMessageCodec.encode(query("u99.e2e.test.", 99))));
            assertEquals(1, tcpResp.getAnswers().size());
            assertRecordExactly(tcpResp.getAnswers().get(0),
                    DnsName.of("u99.e2e.test."), 99, 300, rdata);

            // Authorized AXFR includes the record with its code unmodified.
            DnsMessage axfr = DnsMessageCodec.decode(
                    tcpExchange(h.config().getTcpPort(), axfrRequest()));
            assertEquals(RCode.NOERROR, axfr.getHeader().getRcode());
            long matches = axfr.getAnswers().stream()
                    .filter(r -> r.getName().equals(DnsName.of("u99.e2e.test."))
                            && r.getType() == 99 && r.getTtl() == 300
                            && java.util.Arrays.equals(r.getRdata(), rdata))
                    .count();
            assertEquals(1, matches, "AXFR must carry the TYPE99 record verbatim");
        } finally {
            h.stop();
        }
    }

    @Test
    void singleDigitType9SurvivesRestartAndIsServed() throws Exception {
        byte[] rdata = {0x01, 0x02};
        submitRecord("u9.e2e.test.", "TYPE9", 60, "\\# 2 01 02", 200);

        // Simulate a full service restart on the same data directory.
        DnsServerConfig cfg = new DnsServerConfig();
        cfg.setListenAddress("127.0.0.1");
        cfg.setUdpPort(freePort());
        cfg.setTcpPort(freePort());
        cfg.setDataDir(dir.toString());
        cfg.setZoneFile("zone.dat");
        cfg.setAuditFile("audit-restart.log");
        ZoneStore restartedStore = new ZoneStore();
        DnsServerLifecycle lifecycle = new DnsServerLifecycle(cfg, restartedStore,
                new QueryHandler(restartedStore),
                new ZoneTransferHandler(cfg, restartedStore, new AuditLog()),
                new ZonePersistence(zoneFile), new AuditLog());
        lifecycle.start();
        try {
            Zone recovered = restartedStore.current().orElseThrow();
            DnsRecord r = recovered.lookup(DnsName.of("u9.e2e.test."), 9).get(0);
            assertRecordExactly(r, DnsName.of("u9.e2e.test."), 9, 60, rdata);

            DnsMessage resp = DnsMessageCodec.decode(
                    udpExchange(cfg.getUdpPort(),
                            DnsMessageCodec.encode(query("u9.e2e.test.", 9))));
            assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
            assertEquals(1, resp.getAnswers().size());
            assertRecordExactly(resp.getAnswers().get(0),
                    DnsName.of("u9.e2e.test."), 9, 60, rdata);
        } finally {
            lifecycle.stop();
        }
    }

    @Test
    void multiDigitAndNearMaxTypesSurviveReload() throws Exception {
        submitRecord("u123.e2e.test.", "TYPE123", 61, "\\# 1 0a", 200);
        submitRecord("umax.e2e.test.", "TYPE65535", 62, "\\# 1 0b", 200);

        Zone recovered = new ZonePersistence(zoneFile).load().orElseThrow();
        assertRecordExactly(recovered.lookup(DnsName.of("u123.e2e.test."), 123).get(0),
                DnsName.of("u123.e2e.test."), 123, 61, new byte[]{0x0a});
        assertRecordExactly(recovered.lookup(DnsName.of("umax.e2e.test."), 65535).get(0),
                DnsName.of("umax.e2e.test."), 65535, 62, new byte[]{0x0b});
    }

    @Test
    void invalidTypeRepresentationsAreRejectedAndZoneUntouched() throws Exception {
        int recordsBefore = store.current().orElseThrow().allRecords().size();
        String fileBefore = Files.readString(zoneFile);

        for (String bad : new String[]{"TYPE", "TYPE65536", "TYPE99999", "TYPE-1",
                "TYPE12x", "TYPE+9", "99"}) {
            submitRecord("bad.e2e.test.", bad, 60, "\\# 1 00", 400);
        }

        // A rejected update never reaches the zone or the persisted file.
        assertEquals(recordsBefore, store.current().orElseThrow().allRecords().size());
        assertEquals(fileBefore, Files.readString(zoneFile));
    }
}
