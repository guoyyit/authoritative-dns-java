package com.github.guoyyit.authoritativednsjava.dns.update;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistenceException;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;

/**
 * Authenticated, audited, durable zone updates.
 *
 * <p>Every update is built from the current snapshot into a brand-new immutable
 * {@link Zone}, persisted first, and only then swapped into the store. Queries
 * in flight therefore see either the whole old version or the whole new one.
 * A failure before the swap leaves the committed version untouched.
 */
@Service
public class ZoneUpdateService {

    private static final int CLASS_IN = 1;
    private static final long DEFAULT_REFRESH = 7200;
    private static final long DEFAULT_RETRY = 3600;
    private static final long DEFAULT_EXPIRE = 1_209_600;
    private static final long DEFAULT_MINIMUM = 60;
    private static final DateTimeFormatter SERIAL_DATE = DateTimeFormatter.ofPattern("yyyyMMdd");

    private final DnsServerConfig config;
    private final ZoneStore store;
    private final ZonePersistence persistence;
    private final AuditLog audit;

    public ZoneUpdateService(DnsServerConfig config, ZoneStore store,
                             ZonePersistence persistence, AuditLog audit) {
        this.config = config;
        this.store = store;
        this.persistence = persistence;
        this.audit = audit;
    }

    public synchronized void createZone(String originName, String key)
            throws ZonePersistenceException, AuthorizationException {
        authorize(key, "CREATE", originName);
        DnsName origin = DnsName.of(originName);
        long serial = Long.parseLong(LocalDate.now().format(SERIAL_DATE) + "00");
        DnsRecord soa = new DnsRecord(origin, DnsRecordType.SOA, CLASS_IN, DEFAULT_MINIMUM,
                RData.soaRdata(DnsName.of("ns." + origin),
                        DnsName.of("hostmaster." + origin),
                        serial, DEFAULT_REFRESH, DEFAULT_RETRY, DEFAULT_EXPIRE, DEFAULT_MINIMUM));
        Zone zone = Zone.builder(origin).add(soa).build();
        persistence.save(zone);
        store.replace(zone);
        audit.record("CREATE", actor(key), "zone=" + origin + " serial=" + serial, true);
    }

    /** Atomically applies record additions/removals: persist first, then publish. */
    public synchronized void applyUpdate(List<DnsRecord> add, List<DnsRecord> remove, String key)
            throws ZonePersistenceException, AuthorizationException {
        Optional<Zone> current = store.current();
        if (current.isEmpty()) {
            String detail = "no-zone";
            audit.record("UPDATE", actor(key), detail, false);
            throw new ZonePersistenceException("no zone has been created yet");
        }
        Zone old = current.get();
        authorize(key, "UPDATE", old.getOrigin().toString());

        Zone.Builder builder = Zone.builder(old.getOrigin());
        builder.addAll(old.allRecords());
        if (remove != null) {
            for (DnsRecord r : remove) {
                builder.remove(r);
            }
        }
        if (add != null) {
            for (DnsRecord r : add) {
                builder.add(r);
            }
        }
        Zone next;
        try {
            next = builder.build();
        } catch (IllegalStateException e) {
            // SOA must remain present; uncommitted change never takes effect.
            audit.record("UPDATE", actor(key), "rejected=" + e.getMessage(), false);
            throw new ZonePersistenceException("update rejected: " + e.getMessage(), e);
        }
        persistence.save(next);
        store.replace(next);
        audit.record("UPDATE", actor(key),
                "zone=" + next.getOrigin() + " serial=" + next.getSerial()
                        + " add=" + (add == null ? 0 : add.size())
                        + " remove=" + (remove == null ? 0 : remove.size()), true);
    }

    private void authorize(String presented, String action, String detail)
            throws AuthorizationException {
        if (!keyMatches(config.getUpdateKey(), presented)) {
            audit.record(action, actor(presented), "zone=" + detail + " reason=bad-key", false);
            throw new AuthorizationException("unauthorized " + action + " attempt");
        }
    }

    private boolean keyMatches(String expected, String presented) {
        if (presented == null || expected == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                presented.getBytes(StandardCharsets.UTF_8));
    }

    private String actor(String key) {
        if (key == null) {
            return "anonymous";
        }
        return "key:" + Integer.toHexString(key.hashCode());
    }
}
