package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.update.AuthorizationException;
import com.github.guoyyit.authoritativednsjava.dns.update.ZoneUpdateService;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationAuditTest {

    private static final int IN = 1;

    private static DnsRecord aRecord(String host, String ip) {
        return new DnsRecord(DnsName.of(host), DnsRecordType.A, IN, 300, RData.aRdata(ip));
    }

    private static ZoneUpdateService service(DnsServerConfig config, ZoneStore store,
                                             Path dir, AuditLog audit) throws Exception {
        audit.setFile(dir.resolve("audit.log"));
        return new ZoneUpdateService(config, store,
                new ZonePersistence(dir.resolve("zone.dat")), audit);
    }

    private static DnsServerConfig config(Path dir) {
        DnsServerConfig config = new DnsServerConfig();
        config.setDataDir(dir.toString());
        config.setUpdateKey("master-secret");
        return config;
    }

    @Test
    void unauthorizedCreateIsRejectedAndAudited(@TempDir Path dir) throws Exception {
        ZoneStore store = new ZoneStore();
        AuditLog audit = new AuditLog();
        ZoneUpdateService svc = service(config(dir), store, dir, audit);

        assertThrows(AuthorizationException.class,
                () -> svc.createZone("example.com.", "wrong-secret"));
        assertTrue(store.current().isEmpty(), "no zone may be created on auth failure");
        assertTrue(Files.readString(dir.resolve("audit.log"))
                .contains("action=CREATE actor=key:"));
        assertTrue(Files.readString(dir.resolve("audit.log")).contains("result=DENIED"));
        assertTrue(Files.readString(dir.resolve("audit.log")).contains("reason=bad-key"));
    }

    @Test
    void missingKeyIsRejected(@TempDir Path dir) throws Exception {
        ZoneStore store = new ZoneStore();
        ZoneUpdateService svc = service(config(dir), store, dir, new AuditLog());

        assertThrows(AuthorizationException.class,
                () -> svc.createZone("example.com.", null));
        assertTrue(store.current().isEmpty());
    }

    @Test
    void unauthorizedUpdateDoesNotChangeZoneOrDisk(@TempDir Path dir) throws Exception {
        ZoneStore store = new ZoneStore();
        AuditLog audit = new AuditLog();
        ZoneUpdateService svc = service(config(dir), store, dir, audit);
        svc.createZone("example.com.", "master-secret");
        long serialBefore = store.current().orElseThrow().getSerial();
        byte[] diskBefore = Files.readAllBytes(dir.resolve("zone.dat"));

        assertThrows(AuthorizationException.class,
                () -> svc.applyUpdate(List.of(aRecord("evil.example.com.", "10.0.0.66")),
                        List.of(), "attacker-key"));

        assertEquals(serialBefore, store.current().orElseThrow().getSerial());
        assertTrue(store.current().orElseThrow()
                .lookup(DnsName.of("evil.example.com.")).isEmpty());
        byte[] diskAfter = Files.readAllBytes(dir.resolve("zone.dat"));
        assertEquals(java.util.Arrays.toString(diskBefore), java.util.Arrays.toString(diskAfter),
                "denied update must not touch the committed file");

        String auditText = Files.readString(dir.resolve("audit.log"));
        assertTrue(auditText.contains("action=UPDATE"));
        assertTrue(auditText.contains("result=DENIED"));
        // Allowed and denied events are both traceable in the same trail.
        assertTrue(auditText.contains("action=CREATE"));
        assertTrue(auditText.contains("result=ALLOWED"));
    }

    @Test
    void authorizedUpdateSucceedsAndIsAudited(@TempDir Path dir) throws Exception {
        ZoneStore store = new ZoneStore();
        AuditLog audit = new AuditLog();
        ZoneUpdateService svc = service(config(dir), store, dir, audit);
        svc.createZone("example.com.", "master-secret");
        svc.applyUpdate(List.of(aRecord("ok.example.com.", "10.0.0.1")),
                List.of(), "master-secret");

        assertEquals(1, store.current().orElseThrow()
                .lookup(DnsName.of("ok.example.com."), DnsRecordType.A).size());
        String auditText = Files.readString(dir.resolve("audit.log"));
        assertTrue(auditText.contains("action=UPDATE"));
        assertTrue(auditText.contains("result=ALLOWED"));
    }
}
