package com.github.guoyyit.authoritativednsjava.dns.zone;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Immutable zone snapshot. Readers always see one whole consistent version;
 * updates build a new Zone and swap it atomically in {@link ZoneStore}.
 */
public final class Zone {

    private final DnsName origin;
    private final DnsRecord soa;
    private final Map<DnsName, List<DnsRecord>> records;

    private Zone(DnsName origin, DnsRecord soa, Map<DnsName, List<DnsRecord>> records) {
        this.origin = origin;
        this.soa = soa;
        this.records = records;
    }

    public static Builder builder(DnsName origin) {
        return new Builder(origin);
    }

    public DnsName getOrigin() {
        return origin;
    }

    public long getSerial() {
        return RData.soaSerial(soa.getRdata());
    }

    public DnsRecord getSoa() {
        return soa;
    }

    /** Negative-cache TTL: the SOA minimum field (RFC 2308). */
    public long getNegativeTtl() {
        return RData.soaMinimum(soa.getRdata());
    }

    /** All records owned by {@code name} (empty if the name does not exist). */
    public List<DnsRecord> lookup(DnsName name) {
        return records.getOrDefault(name, List.of());
    }

    /** Records owned by {@code name} with the given type. */
    public List<DnsRecord> lookup(DnsName name, int type) {
        List<DnsRecord> all = lookup(name);
        if (all.isEmpty()) {
            return all;
        }
        List<DnsRecord> out = new ArrayList<>();
        for (DnsRecord r : all) {
            if (r.getType() == type) {
                out.add(r);
            }
        }
        return out;
    }

    /** True if {@code name} exists in the zone (owns at least one record). */
    public boolean exists(DnsName name) {
        return records.containsKey(name);
    }

    /** True if {@code name} is inside this zone (equal to or below the origin). */
    public boolean contains(DnsName name) {
        return name.isSubdomainOf(origin);
    }

    /** All records in deterministic canonical order (used by AXFR/persistence). */
    public List<DnsRecord> allRecords() {
        List<DnsRecord> out = new ArrayList<>();
        for (List<DnsRecord> rs : records.values()) {
            out.addAll(rs);
        }
        return Collections.unmodifiableList(out);
    }

    /** Mutable builder; produces immutable snapshots. */
    public static final class Builder {
        private final DnsName origin;
        private final Map<DnsName, List<DnsRecord>> records = new TreeMap<>();
        private DnsRecord soa;

        private Builder(DnsName origin) {
            this.origin = origin;
        }

        public Builder add(DnsRecord record) {
            if (!record.getName().isSubdomainOf(origin)) {
                throw new IllegalArgumentException(
                        "record owner " + record.getName() + " is outside zone " + origin);
            }
            if (record.getType() == DnsRecordType.SOA) {
                // A zone has exactly one SOA at the apex; replace any prior one.
                if (!record.getName().equals(origin)) {
                    throw new IllegalArgumentException("SOA owner must be the zone apex " + origin);
                }
                List<DnsRecord> existing = records.get(origin);
                if (existing != null) {
                    existing.removeIf(r -> r.getType() == DnsRecordType.SOA);
                }
                this.soa = record;
            }
            records.computeIfAbsent(record.getName(), k -> new ArrayList<>()).add(record);
            return this;
        }

        public Builder addAll(Iterable<DnsRecord> toAdd) {
            for (DnsRecord r : toAdd) {
                add(r);
            }
            return this;
        }

        public Builder remove(DnsRecord record) {
            List<DnsRecord> rs = records.get(record.getName());
            if (rs != null) {
                boolean removed = rs.remove(record);
                if (removed && record.getType() == DnsRecordType.SOA) {
                    this.soa = null; // a zone without SOA cannot be built
                }
                if (rs.isEmpty()) {
                    records.remove(record.getName());
                }
            }
            return this;
        }

        public Zone build() {
            if (soa == null) {
                throw new IllegalStateException("zone " + origin + " has no SOA record");
            }
            Map<DnsName, List<DnsRecord>> copy = new TreeMap<>();
            for (Map.Entry<DnsName, List<DnsRecord>> e : records.entrySet()) {
                copy.put(e.getKey(), Collections.unmodifiableList(new ArrayList<>(e.getValue())));
            }
            return new Zone(origin, soa, Collections.unmodifiableMap(copy));
        }
    }
}
