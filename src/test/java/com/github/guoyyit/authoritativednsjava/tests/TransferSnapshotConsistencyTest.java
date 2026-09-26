package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.server.ZoneTransferHandler;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * AXFR snapshot isolation: while a writer swaps versions, every transferred
 * answer set must come from exactly one snapshot — the SOA serial and the
 * version-specific record owner must agree, with no old/new mixture.
 */
class TransferSnapshotConsistencyTest {

    private static final int IN = 1;
    private static final String KEY = "k";

    private static Zone zoneAt(long serial) {
        DnsName origin = DnsName.of("z.test.");
        return Zone.builder(origin)
                .add(new DnsRecord(origin, DnsRecordType.SOA, IN, 60,
                        RData.soaRdata(DnsName.of("ns.z.test."), DnsName.of("hm.z.test."),
                                serial, 7200, 3600, 100, 60)))
                .add(new DnsRecord(origin, DnsRecordType.NS, IN, 60,
                        RData.nameRdata(DnsName.of("ns.z.test."))))
                .add(new DnsRecord(DnsName.of("v" + serial + ".z.test."), DnsRecordType.TXT, IN, 60,
                        RData.txtRdata("version=" + serial)))
                .build();
    }

    private static DnsMessage axfrQuery() {
        DnsMessage q = new DnsMessage();
        q.getHeader().setId(1);
        q.getHeader().setQr(false);
        q.getQuestions().add(new DnsQuestion(DnsName.of("z.test."), DnsRecordType.AXFR, IN));
        q.getAdditionals().add(new DnsRecord(DnsName.of("key."), DnsRecordType.TXT, IN, 0,
                RData.txtRdata(KEY)));
        return q;
    }

    @Test
    void concurrentUpdatesNeverMixTheTransferredView(@TempDir Path dir) throws Exception {
        DnsServerConfig cfg = new DnsServerConfig();
        cfg.setTransferKey(KEY);
        ZoneStore store = new ZoneStore();
        store.replace(zoneAt(1));
        AuditLog audit = new AuditLog();
        audit.setFile(dir.resolve("audit.log"));
        ZoneTransferHandler xh = new ZoneTransferHandler(cfg, store, audit);

        int transfers = 200;
        int versions = 200;
        AtomicInteger mixed = new AtomicInteger();
        AtomicInteger checked = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(5);

        pool.submit(() -> {
            try {
                start.await();
                for (long s = 2; s <= versions; s++) {
                    store.replace(zoneAt(s));
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        List<java.util.concurrent.Future<?>> readers = new java.util.ArrayList<>();
        for (int i = 0; i < 4; i++) {
            readers.add(pool.submit(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                for (int t = 0; t < transfers / 4; t++) {
                    DnsMessage resp = xh.handle(axfrQuery(), KEY);
                    List<DnsRecord> ans = resp.getAnswers();
                    long serial = RData.soaSerial(ans.get(0).getRdata());
                    // Collect version-specific owners; a coherent view has exactly one.
                    Set<String> owners = new HashSet<>();
                    for (DnsRecord r : ans) {
                        String n = r.getName().toString();
                        if (n.startsWith("v") && n.endsWith(".z.test.")) {
                            owners.add(n);
                        }
                    }
                    if (owners.size() != 1
                            || !owners.contains(DnsName.of("v" + serial + ".z.test.").toString())
                            || RData.soaSerial(ans.get(ans.size() - 1).getRdata()) != serial) {
                        mixed.incrementAndGet();
                    }
                    checked.incrementAndGet();
                }
            }));
        }
        start.countDown();
        for (var f : readers) {
            f.get(15, TimeUnit.SECONDS);
        }
        pool.shutdownNow();
        pool.awaitTermination(2, TimeUnit.SECONDS);

        assertTrue(checked.get() > 0);
        assertEquals(0, mixed.get(), "mixed-version AXFR responses: " + mixed.get());
        assertEquals(versions, store.current().orElseThrow().getSerial());
    }
}
