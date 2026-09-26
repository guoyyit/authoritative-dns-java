package com.github.guoyyit.authoritativednsjava.dns.server;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistenceException;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

/**
 * Wires persistence, recovery and the UDP/TCP listeners. On startup a corrupt
 * zone file aborts the context (fail-fast); with no file yet, a small default
 * zone is committed so the service is immediately reproducible on an
 * unprivileged local port.
 */
@Component
public class DnsServerLifecycle implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(DnsServerLifecycle.class);
    private static final int CLASS_IN = 1;

    private final DnsServerConfig config;
    private final ZoneStore store;
    private final QueryHandler queryHandler;
    private final ZoneTransferHandler transferHandler;
    private final AuditLog audit;
    private final ZonePersistence persistence;

    private UdpDnsServer udpServer;
    private TcpDnsServer tcpServer;
    private volatile boolean started;

    public DnsServerLifecycle(DnsServerConfig config, ZoneStore store,
                              QueryHandler queryHandler, ZoneTransferHandler transferHandler,
                              AuditLog audit, ZonePersistence persistence) {
        this.config = config;
        this.store = store;
        this.queryHandler = queryHandler;
        this.transferHandler = transferHandler;
        this.audit = audit;
        this.persistence = persistence;
    }

    @Override
    public synchronized void start() {
        Path dataDir = Paths.get(config.getDataDir());
        Path zoneFile = persistence.file();
        Path auditFile = dataDir.resolve(config.getAuditFile());
        try {
            audit.setFile(auditFile);
            Optional<Zone> loaded = persistence.load(); // throws on corrupt data
            if (loaded.isPresent()) {
                store.replace(loaded.get());
                log.info("recovered zone {} serial {} from {}",
                        loaded.get().getOrigin(), loaded.get().getSerial(), zoneFile);
            } else {
                Zone seeded = seedZone();
                persistence.save(seeded);
                store.replace(seeded);
                log.info("seeded default zone {} at {}", seeded.getOrigin(), zoneFile);
            }
            udpServer = new UdpDnsServer(config, queryHandler);
            tcpServer = new TcpDnsServer(config, queryHandler, transferHandler);
            udpServer.start();
            tcpServer.start();
            started = true;
        } catch (ZonePersistenceException e) {
            throw new IllegalStateException("refusing to start with corrupt zone data: "
                    + e.getMessage(), e);
        } catch (IOException e) {
            throw new IllegalStateException("cannot initialize data directory: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new IllegalStateException("failed to start DNS listeners: " + e.getMessage(), e);
        }
    }

    /** Deterministic demo zone, reproducible on any machine. */
    private Zone seedZone() {
        DnsName origin = DnsName.of("example.local.");
        long serial = Long.parseLong(LocalDate.now().format(DateTimeFormatter.ofPattern("yyyyMMdd")) + "00");
        DnsRecord soa = new DnsRecord(origin, DnsRecordType.SOA, CLASS_IN, 3600,
                RData.soaRdata(DnsName.of("ns.example.local."), DnsName.of("hostmaster.example.local."),
                        serial, 7200, 3600, 1_209_600, 60));
        Zone.Builder b = Zone.builder(origin)
                .add(soa)
                .add(new DnsRecord(origin, DnsRecordType.NS, CLASS_IN, 3600,
                        RData.nameRdata(DnsName.of("ns.example.local."))))
                .add(new DnsRecord(origin, DnsRecordType.A, CLASS_IN, 300, RData.aRdata("127.0.0.1")))
                .add(new DnsRecord(DnsName.of("ns.example.local."), DnsRecordType.A, CLASS_IN, 300,
                        RData.aRdata("127.0.0.1")))
                .add(new DnsRecord(DnsName.of("www.example.local."), DnsRecordType.A, CLASS_IN, 300,
                        RData.aRdata("127.0.0.2")))
                .add(new DnsRecord(DnsName.of("v6.example.local."), DnsRecordType.AAAA, CLASS_IN, 300,
                        RData.aaaaRdata("::1")))
                .add(new DnsRecord(DnsName.of("alias.example.local."), DnsRecordType.CNAME, CLASS_IN, 300,
                        RData.nameRdata(DnsName.of("www.example.local."))))
                .add(new DnsRecord(DnsName.of("mail.example.local."), DnsRecordType.MX, CLASS_IN, 300,
                        RData.mxRdata(10, DnsName.of("mailhost.example.local."))))
                .add(new DnsRecord(DnsName.of("mailhost.example.local."), DnsRecordType.A, CLASS_IN, 300,
                        RData.aRdata("127.0.0.3")))
                .add(new DnsRecord(DnsName.of("txt.example.local."), DnsRecordType.TXT, CLASS_IN, 300,
                        RData.txtRdata("hello authoritative dns")))
                // Delegation: sub.example.local is served elsewhere.
                .add(new DnsRecord(DnsName.of("sub.example.local."), DnsRecordType.NS, CLASS_IN, 3600,
                        RData.nameRdata(DnsName.of("ns.sub.example.local."))))
                .add(new DnsRecord(DnsName.of("ns.sub.example.local."), DnsRecordType.A, CLASS_IN, 3600,
                        RData.aRdata("127.0.0.4")));
        return b.build();
    }

    @Override
    public synchronized void stop() {
        if (udpServer != null) {
            udpServer.stop();
        }
        if (tcpServer != null) {
            tcpServer.stop();
        }
        started = false;
    }

    @Override
    public boolean isRunning() {
        return started;
    }

    @Override
    public boolean isAutoStartup() {
        return true;
    }
}
