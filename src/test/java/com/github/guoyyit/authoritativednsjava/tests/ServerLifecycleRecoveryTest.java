package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessageCodec;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RCode;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerLifecycle;
import com.github.guoyyit.authoritativednsjava.dns.server.QueryHandler;
import com.github.guoyyit.authoritativednsjava.dns.server.ZoneTransferHandler;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Start/recovery: first run seeds, restart recovers, corrupt file aborts, ports configurable. */
class ServerLifecycleRecoveryTest {

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
        return cfg;
    }

    private static DnsServerLifecycle lifecycle(DnsServerConfig cfg, ZoneStore store,
                                                ZonePersistence persistence, AuditLog audit) {
        QueryHandler qh = new QueryHandler(store);
        ZoneTransferHandler xh = new ZoneTransferHandler(cfg, store, audit);
        return new DnsServerLifecycle(cfg, store, qh, xh, persistence, audit);
    }

    private static DnsMessage udpQuery(int port, String name, int type) throws Exception {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(5);
        q.getQuestions().add(new DnsQuestion(DnsName.of(name), type, 1));
        byte[] req = DnsMessageCodec.encode(q);
        try (DatagramSocket sock = new DatagramSocket()) {
            sock.setSoTimeout(3000);
            sock.send(new DatagramPacket(req, req.length,
                    new InetSocketAddress("127.0.0.1", port)));
            byte[] buf = new byte[2048];
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            sock.receive(p);
            byte[] resp = new byte[p.getLength()];
            System.arraycopy(buf, 0, resp, 0, p.getLength());
            return DnsMessageCodec.decode(resp);
        }
    }

    @Test
    void restartRecoversCommittedZoneInsteadOfReseeding(@TempDir Path dir) throws Exception {
        Path zoneFile = dir.resolve("zone.dat");
        DnsServerConfig cfg1 = config(dir, freePort(), freePort());
        ZoneStore store1 = new ZoneStore();
        ZonePersistence p1 = new ZonePersistence(zoneFile);
        AuditLog audit1 = new AuditLog();
        DnsServerLifecycle lc1 = lifecycle(cfg1, store1, p1, audit1);
        lc1.start();
        long seededSerial = store1.current().orElseThrow().getSerial();
        DnsName origin = store1.current().orElseThrow().getOrigin();
        lc1.stop();

        // Simulate a fresh process: new beans, same file.
        DnsServerConfig cfg2 = config(dir, freePort(), freePort());
        ZoneStore store2 = new ZoneStore();
        ZonePersistence p2 = new ZonePersistence(zoneFile);
        AuditLog audit2 = new AuditLog();
        DnsServerLifecycle lc2 = lifecycle(cfg2, store2, p2, audit2);
        lc2.start();
        try {
            Zone recovered = store2.current().orElseThrow();
            assertEquals(origin, recovered.getOrigin());
            assertEquals(seededSerial, recovered.getSerial(),
                    "restart must recover the committed serial, not reseed");
            // The listener on the configured unprivileged port serves the recovered data.
            DnsMessage resp = udpQuery(cfg2.getUdpPort(), "www.example.local.", DnsRecordType.A);
            assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
            assertEquals(1, resp.getAnswers().size());
        } finally {
            lc2.stop();
        }
    }

    @Test
    void corruptZoneFileAbortsStartup(@TempDir Path dir) throws Exception {
        Path zoneFile = dir.resolve("zone.dat");
        // A valid-looking file with a bad checksum must be refused.
        Files.write(zoneFile,
                ("; zone=example.local.\nbroken payload\n; checksum=deadbeef\n")
                        .getBytes(StandardCharsets.UTF_8));

        DnsServerConfig cfg = config(dir, freePort(), freePort());
        DnsServerLifecycle lc = lifecycle(cfg, new ZoneStore(),
                new ZonePersistence(zoneFile), new AuditLog());
        IllegalStateException e = assertThrows(IllegalStateException.class, lc::start);
        assertTrue(e.getMessage().contains("refusing to start")
                || e.getCause() != null);
    }

    @Test
    void listenerBindsToConfiguredUnprivilegedPorts(@TempDir Path dir) throws Exception {
        int udp = freePort();
        int tcp = freePort();
        DnsServerConfig cfg = config(dir, udp, tcp);
        ZoneStore store = new ZoneStore();
        DnsServerLifecycle lc = lifecycle(cfg, store,
                new ZonePersistence(dir.resolve("zone.dat")), new AuditLog());
        lc.start();
        try {
            assertTrue(lc.isRunning());
            DnsMessage resp = udpQuery(udp, "txt.example.local.", DnsRecordType.TXT);
            assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
            assertEquals(1, resp.getAnswers().size());
        } finally {
            lc.stop();
        }
    }
}
