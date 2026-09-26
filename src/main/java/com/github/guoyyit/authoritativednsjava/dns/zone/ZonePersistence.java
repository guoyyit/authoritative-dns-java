package com.github.guoyyit.authoritativednsjava.dns.zone;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/**
 * File-backed zone persistence.
 *
 * <p>Format: text lines {@code <name> <ttl> <TYPE> <rdata...>}, terminated by a
 * {@code ; checksum=<sha256>} line covering all preceding bytes. Writes go to a
 * temp file, are fsynced, then atomically renamed — so a crash either leaves the
 * old committed version or the new one, never a partial file. A checksum
 * mismatch on load is reported as corruption and startup is refused.
 */
@Component
public class ZonePersistence {

    private static final String CHECKSUM_PREFIX = "; checksum=";

    private final Path file;

    /** Spring wiring: resolves the file from the configurable dns.* properties. */
    @Autowired
    public ZonePersistence(@Value("${dns.data-dir:data}") String dataDir,
                           @Value("${dns.zone-file:zone.dat}") String zoneFile) {
        this(Paths.get(dataDir).resolve(zoneFile));
    }

    /** Direct construction against an explicit file (used by tests/tools). */
    public ZonePersistence(Path file) {
        this.file = file;
    }

    public Path file() {
        return file;
    }

    /** Loads the persisted zone, or empty if none was ever committed. */
    public Optional<Zone> load() throws ZonePersistenceException {
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        final byte[] raw;
        try {
            raw = Files.readAllBytes(file);
        } catch (IOException e) {
            throw new ZonePersistenceException("cannot read zone file " + file, e);
        }
        String content = new String(raw, StandardCharsets.UTF_8);
        int checksumLine = content.lastIndexOf(CHECKSUM_PREFIX);
        if (checksumLine < 0) {
            throw new ZonePersistenceException(
                    "zone file " + file + " has no checksum; refusing to load");
        }
        String body = content.substring(0, checksumLine);
        String expected = content.substring(checksumLine + CHECKSUM_PREFIX.length()).trim();
        String actual = sha256Hex(body.getBytes(StandardCharsets.UTF_8));
        if (!expected.equalsIgnoreCase(actual)) {
            throw new ZonePersistenceException(
                    "zone file " + file + " is corrupt (checksum mismatch)");
        }
        return Optional.of(parse(body));
    }

    /** Durably commits a zone snapshot (write temp file, fsync, atomic rename). */
    public void save(Zone zone) throws ZonePersistenceException {
        StringBuilder body = new StringBuilder();
        body.append("; zone=").append(zone.getOrigin()).append('\n');
        body.append("; serial=").append(zone.getSerial()).append('\n');
        for (DnsRecord r : zone.allRecords()) {
            body.append(r.getName()).append(' ')
                    .append(r.getTtl()).append(' ')
                    .append(DnsRecordType.name(r.getType())).append(' ')
                    .append(RData.toText(r.getType(), r.getRdata()))
                    .append('\n');
        }
        byte[] bodyBytes = body.toString().getBytes(StandardCharsets.UTF_8);
        String checksum = sha256Hex(bodyBytes);
        byte[] full = (body + CHECKSUM_PREFIX + checksum + "\n").getBytes(StandardCharsets.UTF_8);

        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            try (FileChannel channel = FileChannel.open(tmp,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                channel.write(java.nio.ByteBuffer.wrap(full));
                channel.force(true);
            }
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicFailed) {
                // Fallback for filesystems without atomic rename (e.g. some CI mounts).
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new ZonePersistenceException("cannot write zone file " + file, e);
        }
    }

    private static Zone parse(String body) throws ZonePersistenceException {
        DnsName origin = null;
        Zone.Builder builder = null;
        String[] lines = body.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) {
                continue;
            }
            if (line.startsWith(";")) {
                if (line.startsWith("; zone=")) {
                    origin = DnsName.of(line.substring("; zone=".length()).trim());
                    builder = Zone.builder(origin);
                }
                continue; // other comments (e.g. serial) are informational
            }
            if (builder == null) {
                throw new ZonePersistenceException("zone file missing '; zone=' header");
            }
            String[] parts = line.split("\\s+", 4);
            if (parts.length < 4) {
                throw new ZonePersistenceException(
                        "malformed zone line " + (i + 1) + ": " + line);
            }
            try {
                DnsName name = DnsName.of(parts[0]);
                long ttl = Long.parseLong(parts[1]);
                int type = DnsRecordType.parse(parts[2]);
                byte[] rdata = RData.fromText(type, parts[3]);
                builder.add(new DnsRecord(name, type, 1, ttl, rdata));
            } catch (RuntimeException e) {
                throw new ZonePersistenceException(
                        "bad record on line " + (i + 1) + ": " + line, e);
            }
        }
        if (builder == null) {
            throw new ZonePersistenceException("zone file is empty");
        }
        try {
            return builder.build();
        } catch (IllegalStateException | IllegalArgumentException e) {
            throw new ZonePersistenceException("zone file invalid: " + e.getMessage(), e);
        }
    }

    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
