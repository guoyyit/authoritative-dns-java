package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.QueryHandler;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * While updates swap zone snapshots, every in-flight query must observe one
 * whole version: the A and TXT records of www must always come from the same
 * version (A = 10.0.0.v and TXT = "v" are written together per version).
 */
class ZoneConcurrencyTest {

    private static final DnsName ORIGIN = DnsName.of("example.com.");
    private static final DnsName WWW = DnsName.of("www.example.com.");
    private static final int IN = 1;
    private static final int VERSIONS = 400;

    private static Zone version(int v) {
        return Zone.builder(ORIGIN)
                .add(new DnsRecord(ORIGIN, DnsRecordType.SOA, IN, 3600,
                        RData.soaRdata(DnsName.of("ns1.example.com."),
                                DnsName.of("hostmaster.example.com."),
                                v, 7200, 3600, 1209600, 60)))
                .add(new DnsRecord(WWW, DnsRecordType.A, IN, 300,
                        new byte[]{10, 0, (byte) (v >> 8), (byte) (v & 0xFF)}))
                .add(new DnsRecord(WWW, DnsRecordType.TXT, IN, 300,
                        RData.txtRdata(Integer.toString(v))))
                .build();
    }

    @Test
    void queriesNeverSeeMixedVersions() throws Exception {
        ZoneStore store = new ZoneStore();
        store.replace(version(1));
        QueryHandler handler = new QueryHandler(store);

        AtomicBoolean stop = new AtomicBoolean(false);
        List<String> violations = new CopyOnWriteArrayList<>();
        CountDownLatch readersDone = new CountDownLatch(4);

        ExecutorService pool = Executors.newFixedThreadPool(5);
        // Writer: publish VERSIONS successive snapshots.
        pool.submit(() -> {
            for (int v = 2; v <= VERSIONS; v++) {
                store.replace(version(v));
            }
            stop.set(true);
        });
        // Readers: ANY query must always return a self-consistent pair.
        for (int i = 0; i < 4; i++) {
            pool.submit(() -> {
                try {
                    while (!stop.get()) {
                        DnsMessage q = new DnsMessage();
                        q.getQuestions().add(new DnsQuestion(WWW, DnsRecordType.ANY, IN));
                        DnsMessage resp = handler.handle(q);
                        Integer aVersion = null;
                        String txtVersion = null;
                        for (DnsRecord r : resp.getAnswers()) {
                            if (r.getType() == DnsRecordType.A) {
                                byte[] rd = r.getRdata();
                                aVersion = ((rd[2] & 0xFF) << 8) | (rd[3] & 0xFF);
                            } else if (r.getType() == DnsRecordType.TXT) {
                                byte[] rd = r.getRdata();
                                txtVersion = new String(rd, 1, rd[0] & 0xFF);
                            }
                        }
                        if (aVersion == null || txtVersion == null
                                || !txtVersion.equals(Integer.toString(aVersion))) {
                            violations.add("mixed view: A=" + aVersion + " TXT=" + txtVersion);
                        }
                    }
                } finally {
                    readersDone.countDown();
                }
            });
        }
        assertTrue(readersDone.await(60, TimeUnit.SECONDS), "readers did not finish");
        pool.shutdownNow();
        assertTrue(violations.isEmpty(),
                "queries observed mixed versions: " + violations.subList(0, Math.min(5, violations.size())));
    }
}
