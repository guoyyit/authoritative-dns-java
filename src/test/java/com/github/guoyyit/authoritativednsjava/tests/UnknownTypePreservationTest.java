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
import com.github.guoyyit.authoritativednsjava.dns.server.ZoneTransferHandler;
import com.github.guoyyit.authoritativednsjava.dns.update.ZoneAdminController;
import com.github.guoyyit.authoritativednsjava.dns.update.ZoneUpdateService;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
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
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end unknown-type preservation: a record submitted through the admin
 * API as {@code TYPE9}/{@code TYPE99}/{@code TYPE65535} must keep its exact
 * type code in memory, in the zone file, after a restart, and in UDP, TCP and
 * AXFR answers. Invalid type forms are rejected with 400 and change nothing.
 */
class UnknownTypePreservationTest {

    private static final int IN = 1;
    private static final String UPDATE_KEY = "update-key";
    private static final String TRANSFER_KEY = "transfer-key";

    private static int freePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return s.getLocalPort();
        }
    }

    private static DnsServerConfig config(Path dir, int udp, int tcp) {
        DnsServerConfig cfg = new DnsServerConfig();
        cfg.setListenAddress("127.0.0.1");
        cfg.setUdpPort(udp);
        cfg.setTcpPort(tcp);
        cfg.setDataDir(dir.toString());
        cfg.setAuditFile("audit.log");
        cfg.setZoneFile("zone.dat");
        cfg.setUpdateKey(UPDATE_KEY);
        cfg.setTransferKey(TRANSFER_KEY);
        return cfg;
    }

    private static DnsMessage query(String name, int type) {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(7);
        q.getQuestions().add(new DnsQuestion(DnsName.of(name), type, IN));
        return q;
    }

    private static DnsMessage udpQuery(int port, String name, int type) throws Exception {
        byte[] req = DnsMessageCodec.encode(query(name, type));
        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setSoTimeout(3000);
            sock.send(new DatagramPacket(req, req.length,
                    new InetSocketAddress("127.0.0.1", port)));
            byte[] buf = new byte[4096];
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            sock.receive(p);
            byte[] resp = new byte[p.getLength()];
            System.arraycopy(buf, 0, resp, 0, p.getLength());
            return DnsMessageCodec.decode(resp);
        }
    }

    private static DnsMessage tcpExchange(int port, DnsMessage q) throws Exception {
        byte[] req = DnsMessageCodec.encode(q);
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", port), 3000);
            s.setSoTimeout(3000);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            out.writeShort(req.length);
            out.write(req);
            out.flush();
            DataInputStream in = new DataInputStream(s.getInputStream());
            int len = in.readUnsignedShort();
            byte[] resp = new byte[len];
            in.readFully(resp);
            return DnsMessageCodec.decode(resp);
        }
    }

    private static DnsMessage axfrQuery(String origin) {
        DnsMessage q = query(origin, DnsRecordType.AXFR);
        q.getAdditionals().add(new DnsRecord(DnsName.of("key."), DnsRecordType.TXT, IN, 0,
                RData.txtRdata(TRANSFER_KEY)));
        return q;
    }

    private static DnsRecord findRecord(List<DnsRecord> records, String name, int type) {
        DnsName wanted = DnsName.of(name);
        for (DnsRecord r : records) {
            if (r.getName().equals(wanted) && r.getType() == type) {
                return r;
            }
        }
        return null;
    }

    @Test
    void persistenceRoundTripPreservesEveryFieldOfUnknownTypes(@TempDir Path dir)
            throws Exception {
        DnsName origin = DnsName.of("round.trip.");
        Zone zone = Zone.builder(origin)
                .add(new DnsRecord(origin, DnsRecordType.SOA, IN, 3600,
                        RData.soaRdata(DnsName.of("ns.round.trip."), DnsName.of("hm.round.trip."),
                                42, 7200, 3600, 100, 60)))
                .add(new DnsRecord(origin, DnsRecordType.A, IN, 300, RData.aRdata("192.0.2.1")))
                .add(new DnsRecord(DnsName.of("t.round.trip."), DnsRecordType.TXT, IN, 60,
                        RData.txtRdata("known types still round trip")))
                .add(new DnsRecord(DnsName.of("u9.round.trip."), 9, IN, 61,
                        new byte[]{0x0a, 0x00, 0x00, 0x01}))
                .add(new DnsRecord(DnsName.of("u99.round.trip."), 99, IN, 62,
                        new byte[]{0x01, 0x02, 0x03}))
                .add(new DnsRecord(DnsName.of("umax.round.trip."), 65535, IN, 63,
                        new byte[]{(byte) 0xff}))
                .build();
        Path file = dir.resolve("zone.dat");
        new ZonePersistence(file).save(zone);

        String persisted = Files.readString(file);
        assertTrue(persisted.contains("TYPE9 "), "file must keep the single-digit code");
        assertTrue(persisted.contains("TYPE99 "), "file must keep all digits of the code");
        assertTrue(persisted.contains("TYPE65535 "), "file must keep the max-range code");

        Zone recovered = new ZonePersistence(file).load().orElseThrow();
        assertEquals(zone.allRecords(), recovered.allRecords(),
                "name/type/ttl/class/rdata of every record must survive the round trip");
    }

    @Test
    void submittedUnknownTypesSurviveRestartAndAreServedVerbatim(@TempDir Path dir)
            throws Exception {
        Path zoneFile = dir.resolve("zone.dat");
        DnsServerConfig cfg = config(dir, freePort(), freePort());
        ZoneStore store = new ZoneStore();
        ZonePersistence persistence = new ZonePersistence(zoneFile);
        AuditLog audit = new AuditLog();
        audit.setFile(dir.resolve("audit.log"));
        ZoneUpdateService svc = new ZoneUpdateService(cfg, store, persistence, audit);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new ZoneAdminController(svc, store)).build();

        mvc.perform(post("/zones").param("origin", "e2e.test.").header("X-Update-Key", UPDATE_KEY))
                .andExpect(status().isOk());
        String body = """
                {"add":[
                  {"name":"u9.e2e.test.","type":"TYPE9","ttl":61,"rdata":"\\\\# 4 0a 00 00 01"},
                  {"name":"u99.e2e.test.","type":"TYPE99","ttl":62,"rdata":"\\\\# 3 01 02 03"},
                  {"name":"umax.e2e.test.","type":"TYPE65535","ttl":63,"rdata":"\\\\# 1 ff"}
                ],"remove":[]}
                """;
        mvc.perform(post("/zones/records").header("X-Update-Key", UPDATE_KEY)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk());

        // In-memory view keeps the exact codes right after submission.
        Zone live = store.current().orElseThrow();
        assertEquals(9, findRecord(live.allRecords(), "u9.e2e.test.", 9).getType());
        assertEquals(99, findRecord(live.allRecords(), "u99.e2e.test.", 99).getType());
        assertEquals(65535, findRecord(live.allRecords(), "umax.e2e.test.", 65535).getType());

        // The committed file spells the codes out in full.
        String persisted = Files.readString(zoneFile);
        assertTrue(persisted.contains("TYPE9 "), persisted);
        assertTrue(persisted.contains("TYPE99 "), persisted);
        assertTrue(persisted.contains("TYPE65535 "), persisted);

        // Restart: brand-new beans recover the committed zone from disk.
        DnsServerConfig cfg2 = config(dir, freePort(), freePort());
        ZoneStore store2 = new ZoneStore();
        AuditLog audit2 = new AuditLog();
        DnsServerLifecycle lc = new DnsServerLifecycle(cfg2, store2, new QueryHandler(store2),
                new ZoneTransferHandler(cfg2, store2, audit2),
                new ZonePersistence(zoneFile), audit2);
        lc.start();
        try {
            Zone recovered = store2.current().orElseThrow();
            assertEquals(live.allRecords(), recovered.allRecords(),
                    "restart must recover every record field-for-field");

            DnsMessage udp = udpQuery(cfg2.getUdpPort(), "u99.e2e.test.", 99);
            assertEquals(RCode.NOERROR, udp.getHeader().getRcode());
            assertEquals(1, udp.getAnswers().size());
            assertEquals(99, udp.getAnswers().get(0).getType());
            assertEquals(62, udp.getAnswers().get(0).getTtl());
            assertEquals(IN, udp.getAnswers().get(0).getRrclass());
            org.junit.jupiter.api.Assertions.assertArrayEquals(
                    new byte[]{0x01, 0x02, 0x03}, udp.getAnswers().get(0).getRdata());

            DnsMessage tcp = tcpExchange(cfg2.getTcpPort(), query("u9.e2e.test.", 9));
            assertEquals(RCode.NOERROR, tcp.getHeader().getRcode());
            assertEquals(1, tcp.getAnswers().size());
            assertEquals(9, tcp.getAnswers().get(0).getType());
            org.junit.jupiter.api.Assertions.assertArrayEquals(
                    new byte[]{0x0a, 0x00, 0x00, 0x01}, tcp.getAnswers().get(0).getRdata());

            DnsMessage axfr = tcpExchange(cfg2.getTcpPort(), axfrQuery("e2e.test."));
            assertEquals(RCode.NOERROR, axfr.getHeader().getRcode());
            DnsRecord t9 = findRecord(axfr.getAnswers(), "u9.e2e.test.", 9);
            DnsRecord t99 = findRecord(axfr.getAnswers(), "u99.e2e.test.", 99);
            DnsRecord tmax = findRecord(axfr.getAnswers(), "umax.e2e.test.", 65535);
            assertTrue(t9 != null && t99 != null && tmax != null,
                    "AXFR must carry the unknown-type records with their original codes");
            assertEquals(61, t9.getTtl());
            assertEquals(63, tmax.getTtl());
            org.junit.jupiter.api.Assertions.assertArrayEquals(new byte[]{(byte) 0xff},
                    tmax.getRdata());
        } finally {
            lc.stop();
        }
    }

    @Test
    void invalidTypeRepresentationsAreRejectedAndChangeNothing(@TempDir Path dir)
            throws Exception {
        DnsServerConfig cfg = config(dir, freePort(), freePort());
        ZoneStore store = new ZoneStore();
        ZonePersistence persistence = new ZonePersistence(dir.resolve("zone.dat"));
        AuditLog audit = new AuditLog();
        audit.setFile(dir.resolve("audit.log"));
        ZoneUpdateService svc = new ZoneUpdateService(cfg, store, persistence, audit);
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new ZoneAdminController(svc, store)).build();

        mvc.perform(post("/zones").param("origin", "bad.test.").header("X-Update-Key", UPDATE_KEY))
                .andExpect(status().isOk());
        int committedRecords = store.current().orElseThrow().allRecords().size();

        for (String bad : List.of("TYPE65536", "TYPEabc", "TYPE", "TYPE9x", "TYPE-1", "bogus")) {
            String body = """
                    {"add":[{"name":"x.bad.test.","type":"%s","ttl":60,"rdata":"\\\\# 1 00"}],
                     "remove":[]}
                    """.formatted(bad);
            mvc.perform(post("/zones/records").header("X-Update-Key", UPDATE_KEY)
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest())
                    .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                            .jsonPath("$.error").exists());
        }
        assertEquals(committedRecords, store.current().orElseThrow().allRecords().size(),
                "rejected updates must not alter the committed zone");
    }
}
