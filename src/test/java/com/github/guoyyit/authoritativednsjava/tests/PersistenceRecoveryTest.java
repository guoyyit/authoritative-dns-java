package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistenceException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Durability and recovery: save/load round trip, corrupt file refusal, crash model. */
class PersistenceRecoveryTest {

    private static final int IN = 1;

    @TempDir
    Path dir;
    private Path file;

    @BeforeEach
    void setUp() {
        file = dir.resolve("zone.dat");
    }

    private Zone sampleZone() {
        DnsName origin = DnsName.of("example.test.");
        return Zone.builder(origin)
                .add(new DnsRecord(origin, DnsRecordType.SOA, IN, 3600,
                        RData.soaRdata(DnsName.of("ns.example.test."),
                                DnsName.of("hm.example.test."), 2024010101L,
                                7200, 3600, 100, 60)))
                .add(new DnsRecord(origin, DnsRecordType.NS, IN, 3600,
                        RData.nameRdata(DnsName.of("ns.example.test."))))
                .add(new DnsRecord(DnsName.of("host.example.test."), DnsRecordType.TXT, IN, 60,
                        RData.txtRdata("persisted value")))
                .build();
    }

    @Test
    void missingFileLoadsEmpty() throws Exception {
        assertTrue(new ZonePersistence(file).load().isEmpty());
    }

    @Test
    void saveThenLoadRecoversCommittedZone() throws Exception {
        ZonePersistence p = new ZonePersistence(file);
        Zone zone = sampleZone();
        p.save(zone);

        // Simulate restart: a brand-new persistence instance reads the same file.
        Optional<Zone> recovered = new ZonePersistence(file).load();
        assertTrue(recovered.isPresent());
        Zone r = recovered.get();
        assertEquals(DnsName.of("example.test."), r.getOrigin());
        assertEquals(2024010101L, r.getSerial());
        assertEquals(zone.allRecords().size(), r.allRecords().size());
        DnsRecord txt = r.lookup(DnsName.of("host.example.test."), DnsRecordType.TXT).get(0);
        assertEquals("\"persisted value\"", RData.toText(DnsRecordType.TXT, txt.getRdata()));
    }

    @Test
    void repeatedCommitsAllSurviveInOrder() throws Exception {
        ZonePersistence p = new ZonePersistence(file);
        for (int i = 1; i <= 5; i++) {
            DnsName origin = DnsName.of("example.test.");
            Zone z = Zone.builder(origin)
                    .add(new DnsRecord(origin, DnsRecordType.SOA, IN, 3600,
                            RData.soaRdata(DnsName.of("ns.example.test."),
                                    DnsName.of("hm.example.test."), i, 7200, 3600, 100, 60)))
                    .build();
            p.save(z);
        }
        Zone recovered = new ZonePersistence(file).load().orElseThrow();
        assertEquals(5, recovered.getSerial());
    }

    @Test
    void tamperedFileIsRejected() throws Exception {
        new ZonePersistence(file).save(sampleZone());
        byte[] raw = Files.readAllBytes(file);
        // Flip a payload byte inside a record (after the 12-byte header lines).
        int idx = 40;
        raw[idx] ^= 0xFF;
        Files.write(file, raw);

        ZonePersistenceException e = assertThrows(ZonePersistenceException.class,
                () -> new ZonePersistence(file).load());
        assertTrue(e.getMessage().contains("corrupt"));
    }

    @Test
    void fileWithoutChecksumIsRejected() throws IOException {
        Files.write(file, "; zone=example.test.\n".getBytes(StandardCharsets.UTF_8));
        assertThrows(ZonePersistenceException.class,
                () -> new ZonePersistence(file).load());
    }

    @Test
    void truncatedCommittedFileIsRejectedNotPartiallyLoaded() throws Exception {
        new ZonePersistence(file).save(sampleZone());
        byte[] raw = Files.readAllBytes(file);
        // Simulate a crash tearing the file after half its bytes; checksum must fail.
        Files.write(file, java.util.Arrays.copyOf(raw, raw.length / 2));
        assertThrows(ZonePersistenceException.class,
                () -> new ZonePersistence(file).load());
    }

    @Test
    void noTempFileLeftAfterCommit() throws Exception {
        ZonePersistence p = new ZonePersistence(file);
        p.save(sampleZone());
        try (var stream = Files.list(dir)) {
            assertTrue(stream.noneMatch(f -> f.getFileName().toString().endsWith(".tmp")));
        } catch (IOException ignored) {
        }
    }
}
