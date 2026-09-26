package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.update.ZoneUpdateService;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistenceException;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PersistenceRecoveryTest {

    private static final DnsName ORIGIN = DnsName.of("example.com.");
    private static final int IN = 1;

    private static Zone sampleZone() {
        return Zone.builder(ORIGIN)
                .add(new DnsRecord(ORIGIN, DnsRecordType.SOA, IN, 3600,
                        RData.soaRdata(DnsName.of("ns1.example.com."),
                                DnsName.of("hostmaster.example.com."),
                                2024010100L, 7200, 3600, 1209600, 60)))
                .add(new DnsRecord(ORIGIN, DnsRecordType.NS, IN, 3600,
                        RData.nameRdata(DnsName.of("ns1.example.com."))))
                .add(new DnsRecord(DnsName.of("www.example.com."), DnsRecordType.A, IN, 300,
                        RData.aRdata("192.0.2.10")))
                .add(new DnsRecord(DnsName.of("www.example.com."), DnsRecordType.TXT, IN, 300,
                        RData.txtRdata("hello \"quoted\" text")))
                .add(new DnsRecord(DnsName.of("v6.example.com."), DnsRecordType.AAAA, IN, 300,
                        RData.aaaaRdata("2001:db8::1")))
                .add(new DnsRecord(DnsName.of("weird.example.com."), 99, IN, 60,
                        new byte[]{(byte) 0xDE, (byte) 0xAD}))
                .build();
    }

    @Test
    void saveLoadRoundTrip(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("zone.dat");
        ZonePersistence persistence = new ZonePersistence(file);
        Zone zone = sampleZone();
        persistence.save(zone);

        Optional<Zone> loaded = new ZonePersistence(file).load();
        assertTrue(loaded.isPresent());
        assertEquals(zone.getOrigin(), loaded.get().getOrigin());
        assertEquals(zone.getSerial(), loaded.get().getSerial());
        assertEquals(zone.allRecords().size(), loaded.get().allRecords().size());
        for (DnsRecord r : zone.allRecords()) {
            assertTrue(loaded.get().allRecords().contains(r), "missing record " + r);
        }
    }

    @Test
    void missingFileYieldsEmpty(@TempDir Path dir) throws Exception {
        assertTrue(new ZonePersistence(dir.resolve("nope.dat")).load().isEmpty());
    }

    @Test
    void corruptFileIsRejected(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("zone.dat");
        new ZonePersistence(file).save(sampleZone());
        // Flip a byte in the middle of the file, breaking the checksum.
        byte[] raw = Files.readAllBytes(file);
        raw[raw.length / 2] ^= 0x5A;
        Files.write(file, raw);
        assertThrows(ZonePersistenceException.class, () -> new ZonePersistence(file).load());
    }

    @Test
    void fileWithoutChecksumIsRejected(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("zone.dat");
        Files.writeString(file, "www.example.com. 300 A 192.0.2.1\n");
        assertThrows(ZonePersistenceException.class, () -> new ZonePersistence(file).load());
    }

    @Test
    void crashBeforeRenameKeepsOldCommittedVersion(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("zone.dat");
        ZonePersistence persistence = new ZonePersistence(file);
        Zone v1 = sampleZone();
        persistence.save(v1);

        // Simulate a crash mid-save: a stray temp file exists but the main
        // file was never replaced.
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.writeString(tmp, "garbage partial write");

        Optional<Zone> loaded = new ZonePersistence(file).load();
        assertTrue(loaded.isPresent());
        assertEquals(v1.getSerial(), loaded.get().getSerial());
        assertEquals(v1.allRecords().size(), loaded.get().allRecords().size());
    }

    @Test
    void committedUpdateSurvivesRestart(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("zone.dat");
        DnsServerConfig config = new DnsServerConfig();
        config.setUpdateKey("secret");

        // "First boot": create zone and apply an update.
        ZoneStore store1 = new ZoneStore();
        ZoneUpdateService service1 = new ZoneUpdateService(config, store1,
                new ZonePersistence(file), new AuditLog());
        service1.createZone("example.com.", "secret");
        service1.applyUpdate(
                List.of(new DnsRecord(DnsName.of("new.example.com."), DnsRecordType.A, IN, 300,
                        RData.aRdata("192.0.2.77"))),
                List.of(), "secret");

        // "Restart": fresh store, load from disk.
        ZoneStore store2 = new ZoneStore();
        Optional<Zone> recovered = new ZonePersistence(file).load();
        assertTrue(recovered.isPresent());
        store2.replace(recovered.get());
        Zone zone = store2.current().orElseThrow();
        assertEquals(1, zone.lookup(DnsName.of("new.example.com."), DnsRecordType.A).size());
        assertEquals("192.0.2.77", RData.toText(DnsRecordType.A,
                zone.lookup(DnsName.of("new.example.com."), DnsRecordType.A).get(0).getRdata()));
    }

    @Test
    void failedUpdateLeavesCommittedVersionUntouched(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("zone.dat");
        DnsServerConfig config = new DnsServerConfig();
        config.setUpdateKey("secret");
        ZoneStore store = new ZoneStore();
        ZoneUpdateService service = new ZoneUpdateService(config, store,
                new ZonePersistence(file), new AuditLog());
        service.createZone("example.com.", "secret");
        long serialBefore = store.current().orElseThrow().getSerial();

        // An update that removes the SOA must be rejected and never committed.
        DnsRecord soa = store.current().orElseThrow().getSoa();
        assertThrows(ZonePersistenceException.class,
                () -> service.applyUpdate(List.of(), List.of(soa), "secret"));

        assertEquals(serialBefore, store.current().orElseThrow().getSerial());
        Optional<Zone> onDisk = new ZonePersistence(file).load();
        assertTrue(onDisk.isPresent());
        assertEquals(serialBefore, onDisk.get().getSerial());
    }
}
