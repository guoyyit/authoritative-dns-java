package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RCode;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.server.ZoneTransferHandler;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZoneTransferAuthTest {

    private static final DnsName ORIGIN = DnsName.of("example.com.");
    private static final DnsName KEY_OWNER = DnsName.of("key.");
    private static final int IN = 1;

    private static Zone zoneWithVersion(int records, long serial) {
        Zone.Builder b = Zone.builder(ORIGIN)
                .add(new DnsRecord(ORIGIN, DnsRecordType.SOA, IN, 3600,
                        RData.soaRdata(DnsName.of("ns1.example.com."),
                                DnsName.of("hm.example.com."), serial, 7200, 3600, 1209600, 60)));
        for (int i = 1; i <= records; i++) {
            b.add(new DnsRecord(DnsName.of("h" + i + ".example.com."), DnsRecordType.A, IN, 300,
                    new byte[]{10, 0, (byte) (i >> 8), (byte) i}));
        }
        return b.build();
    }

    private static DnsMessage axfrQuery() {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(9);
        q.getQuestions().add(new DnsQuestion(ORIGIN, DnsRecordType.AXFR, IN));
        return q;
    }

    private static void addKey(DnsMessage q, String key) {
        if (key != null) {
            q.getAdditionals().add(new DnsRecord(KEY_OWNER, DnsRecordType.TXT, IN, 0,
                    RData.txtRdata(key)));
        }
    }

    @Test
    void authorizedAxfrReturnsCompleteSelfConsistentZone(@TempDir Path dir) throws Exception {
        DnsServerConfig config = configWith(dir, "good-key");
        ZoneStore store = new ZoneStore();
        AuditLog audit = new AuditLog();
        audit.setFile(dir.resolve("audit.log"));
        Zone zone = zoneWithVersion(10, 42);
        store.replace(zone);
        ZoneTransferHandler handler = new ZoneTransferHandler(config, store, audit);

        DnsMessage query = axfrQuery();
        addKey(query, "good-key");
        DnsMessage resp = handler.handle(query, "good-key");

        assertEquals(RCode.NOERROR, resp.getHeader().getRcode());
        assertTrue(resp.getHeader().isAa());
        List<DnsRecord> answers = resp.getAnswers();
        assertEquals(DnsRecordType.SOA, answers.get(0).getType(), "AXFR starts with SOA");
        assertEquals(DnsRecordType.SOA, answers.get(answers.size() - 1).getType(),
                "AXFR ends with SOA");
        assertEquals(zone.allRecords().size() + 2, answers.size());
        for (DnsRecord r : zone.allRecords()) {
            assertTrue(answers.contains(r), "AXFR must include every zone record: " + r);
        }
        assertEquals(zone.getSoa(), answers.get(0));
        assertEquals(zone.getSoa(), answers.get(answers.size() - 1));
        assertEquals(42L, RData.soaSerial(answers.get(0).getRdata()));

        String auditText = Files.readString(dir.resolve("audit.log"));
        assertTrue(auditText.contains("action=AXFR"));
        assertTrue(auditText.contains("result=ALLOWED"));
    }

    @Test
    void wrongKeyIsRefusedAndAudited(@TempDir Path dir) throws Exception {
        DnsServerConfig config = configWith(dir, "good-key");
        ZoneStore store = new ZoneStore();
        AuditLog audit = new AuditLog();
        audit.setFile(dir.resolve("audit.log"));
        store.replace(zoneWithVersion(5, 1));
        ZoneTransferHandler handler = new ZoneTransferHandler(config, store, audit);

        DnsMessage query = axfrQuery();
        addKey(query, "wrong-key");
        DnsMessage resp = handler.handle(query, "wrong-key");

        assertEquals(RCode.REFUSED, resp.getHeader().getRcode());
        assertTrue(resp.getAnswers().isEmpty());
        String auditText = Files.readString(dir.resolve("audit.log"));
        assertTrue(auditText.contains("action=AXFR"));
        assertTrue(auditText.contains("result=DENIED"));
        assertTrue(auditText.contains("reason=bad-key"));
    }

    @Test
    void missingKeyIsRefused(@TempDir Path dir) throws Exception {
        DnsServerConfig config = configWith(dir, "good-key");
        ZoneStore store = new ZoneStore();
        AuditLog audit = new AuditLog();
        store.replace(zoneWithVersion(5, 1));
        ZoneTransferHandler handler = new ZoneTransferHandler(config, store, audit);

        DnsMessage resp = handler.handle(axfrQuery(), null);
        assertEquals(RCode.REFUSED, resp.getHeader().getRcode());
        assertTrue(resp.getAnswers().isEmpty());
    }

    @Test
    void transfersDuringUpdatesAreNeverMixed(@TempDir Path dir) throws Exception {
        DnsServerConfig config = configWith(dir, "k");
        ZoneStore store = new ZoneStore();
        store.replace(zoneWithVersion(1, 1));
        ZoneTransferHandler handler =
                new ZoneTransferHandler(config, store, new AuditLog());

        AtomicBoolean stop = new AtomicBoolean(false);
        List<String> violations = new CopyOnWriteArrayList<>();
        ExecutorService pool = Executors.newFixedThreadPool(3);

        // Two transfer readers, continuously authorized.
        CountDownLatch readersDone = new CountDownLatch(2);
        for (int r = 0; r < 2; r++) {
            pool.submit(() -> {
                try {
                    while (!stop.get()) {
                        DnsMessage query = axfrQuery();
                        addKey(query, "k");
                        DnsMessage resp = handler.handle(query, "k");
                        List<DnsRecord> answers = resp.getAnswers();
                        if (answers.size() < 2) {
                            violations.add("too few records");
                            continue;
                        }
                        long serial = RData.soaSerial(answers.get(0).getRdata());
                        // self-consistent: size = records(=serial) + zone SOA + two framing SOAs
                        long expected = serial + 3;
                        if (answers.size() != expected
                                || RData.soaSerial(answers.get(answers.size() - 1).getRdata()) != serial) {
                            violations.add("inconsistent transfer: serial=" + serial
                                    + " size=" + answers.size());
                        }
                    }
                } finally {
                    readersDone.countDown();
                }
            });
        }
        // Updater publishes 200 new snapshots with different record counts.
        pool.submit(() -> {
            for (int v = 2; v <= 200; v++) {
                store.replace(zoneWithVersion((int) v, v));
            }
            stop.set(true);
        });

        assertTrue(readersDone.await(60, TimeUnit.SECONDS));
        pool.shutdownNow();
        assertTrue(violations.isEmpty(),
                "transfers observed mixed zone views: " + violations.subList(0, Math.min(5, violations.size())));
    }

    private DnsServerConfig configWith(Path dir, String key) {
        DnsServerConfig config = new DnsServerConfig();
        config.setDataDir(dir.toString());
        config.setTransferKey(key);
        return config;
    }
}
