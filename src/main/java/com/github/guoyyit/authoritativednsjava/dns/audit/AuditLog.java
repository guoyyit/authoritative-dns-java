package com.github.guoyyit.authoritativednsjava.dns.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Append-only audit trail for zone updates and zone transfers.
 * Each entry is one timestamped line; denied (unauthorized) attempts are
 * recorded too, so they can be traced.
 */
@Component
public class AuditLog {

    private static final Logger log = LoggerFactory.getLogger(AuditLog.class);

    private final ReentrantLock lock = new ReentrantLock();
    private Path file;

    public AuditLog() {
    }

    public void setFile(Path file) throws IOException {
        lock.lock();
        try {
            this.file = file;
            if (file != null) {
                Files.createDirectories(file.toAbsolutePath().getParent());
            }
        } finally {
            lock.unlock();
        }
    }

    public Path getFile() {
        return file;
    }

    public void record(String action, String actor, String detail, boolean allowed) {
        String line = Instant.now().toString()
                + " action=" + action
                + " actor=" + (actor == null ? "anonymous" : actor)
                + " result=" + (allowed ? "ALLOWED" : "DENIED")
                + " detail=" + escape(detail)
                + "\n";
        if (allowed) {
            log.info("AUDIT {}", line.trim());
        } else {
            log.warn("AUDIT {}", line.trim());
        }
        if (file == null) {
            return;
        }
        lock.lock();
        try (OutputStream out = Files.newOutputStream(file,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            out.write(line.getBytes(StandardCharsets.UTF_8));
            out.flush();
        } catch (IOException e) {
            log.error("failed to write audit entry: {}", e.toString());
        } finally {
            lock.unlock();
        }
    }

    private static String escape(String s) {
        if (s == null) {
            return "-";
        }
        return s.replace(' ', '_').replace('\n', ' ');
    }
}
