package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.update.AuthorizationException;
import com.github.guoyyit.authoritativednsjava.dns.update.ZoneUpdateService;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistenceException;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Concurrent updates vs queries: a reader must observe exactly one whole
 * snapshot — a coherent (serial, recordCount) pair — never a mix of versions.
 */
class ZoneConcurrencyTest {

    private static final int IN = 1;
    private static final String KEY = "k";

    private Zone baseZone(long serial) {
        DnsName origin = DnsName.of("z.test.");
        return Zone.builder(origin)
                .add(new DnsRecord(origin, DnsRecordType.SOA, IN, 60,
                        RData.soaRdata(DnsName.of("ns.z.test."), DnsName.of("hm.z.test."),
                                serial, 7200, 3600, 100, 60)))
                .add(new DnsRecord(DnsName.of("r" + serial + ".z.test."), DnsRecordType.A, IN, 60,
                        RData.aRdata("10.0.0." + (serial % 250 + 1))))
                .build();
    }

    @Test
    void readersAlwaysSeeACoherentSnapshot() throws Exception {
        ZoneStore store = new ZoneStore();
        store.replace(baseZone(1));
        int iterations = 200;
        int readers = 6;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger mismatches = new AtomicInteger();
        AtomicInteger observed = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(readers + 1);

        // Writer swaps whole snapshots built with matching serial/owner pairs.
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 2; i <= iterations; i++) {
                    store.replace(baseZone(i));
                }
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        });

        List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
        for (int r = 0; r < readers; r++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                while (System.nanoTime() < deadline) {
                    Zone z = store.current().orElseThrow();
                    long serial = z.getSerial();
                    DnsName expectedOwner = DnsName.of("r" + serial + ".z.test.");
                    if (z.lookup(expectedOwner, DnsRecordType.A).isEmpty()) {
                        mismatches.incrementAndGet(); // mixed old/new fields
                    }
                    observed.incrementAndGet();
                }
            }));
        }
        start.countDown();
        for (var f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdownNow();
        pool.awaitTermination(2, TimeUnit.SECONDS);

        assertTrue(observed.get() > 0);
        assertEquals(0, mismatches.get(),
                "readers observed mixed snapshots: " + mismatches.get());
        assertEquals(iterations, store.current().orElseThrow().getSerial());
    }

    @Test
    void updatesAreSerializedAndEveryCommittedOneIsDurable(@TempDir Path dir) throws Exception {
        DnsServerConfig cfg = new DnsServerConfig();
        cfg.setUpdateKey(KEY);
        ZoneStore store = new ZoneStore();
        ZonePersistence persistence = new ZonePersistence(dir.resolve("zone.dat"));
        AuditLog audit = new AuditLog();
        ZoneUpdateService svc = new ZoneUpdateService(cfg, store, persistence, audit);
        svc.createZone("z.test.", KEY);

        int n = 40;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<java.util.concurrent.Future<?>> fs = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            final int idx = i;
            fs.add(pool.submit(() -> {
                try {
                    start.await();
                    List<DnsRecord> add = List.of(new DnsRecord(
                            DnsName.of("h" + idx + ".z.test."), DnsRecordType.A, IN, 60,
                            RData.aRdata("10.0.0." + (idx % 250 + 1))));
                    svc.applyUpdate(add, List.of(), KEY);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (ZonePersistenceException | AuthorizationException e) {
                    throw new RuntimeException(e);
                }
            }));
        }
        start.countDown();
        for (var f : fs) {
            f.get(15, TimeUnit.SECONDS);
        }
        pool.shutdownNow();

        // All n additions must be present in the single published snapshot...
        Zone finalZone = store.current().orElseThrow();
        for (int i = 0; i < n; i++) {
            assertEquals(1,
                    finalZone.lookup(DnsName.of("h" + i + ".z.test."), DnsRecordType.A).size(),
                    "missing h" + i);
        }
        // ...and recoverable after "restart" from the durable file.
        Zone recovered = persistence.load().orElseThrow();
        for (int i = 0; i < n; i++) {
            assertEquals(1,
                    recovered.lookup(DnsName.of("h" + i + ".z.test."), DnsRecordType.A).size());
        }
    }

    @Test
    void unauthorizedConcurrentUpdatesChangeNothing(@TempDir Path dir) throws Exception {
        DnsServerConfig cfg = new DnsServerConfig();
        cfg.setUpdateKey(KEY);
        ZoneStore store = new ZoneStore();
        ZonePersistence persistence = new ZonePersistence(dir.resolve("zone.dat"));
        AuditLog audit = new AuditLog();
        ZoneUpdateService svc = new ZoneUpdateService(cfg, store, persistence, audit);
        svc.createZone("z.test.", KEY);
        long recordsBefore = store.current().orElseThrow().allRecords().size();

        List<DnsRecord> add = List.of(new DnsRecord(DnsName.of("evil.z.test."),
                DnsRecordType.TXT, IN, 60, RData.txtRdata("nope")));
        assertThrows(AuthorizationException.class,
                () -> svc.applyUpdate(add, List.of(), "wrong-key"));
        assertThrows(AuthorizationException.class,
                () -> svc.applyUpdate(add, List.of(), null));
        assertEquals(recordsBefore, store.current().orElseThrow().allRecords().size());
    }
}
