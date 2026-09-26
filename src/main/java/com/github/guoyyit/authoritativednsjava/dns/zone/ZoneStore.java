package com.github.guoyyit.authoritativednsjava.dns.zone;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds the current zone snapshot. Updates swap the whole snapshot atomically,
 * so a query in flight always sees either the complete old or complete new
 * version — never a mix of records or fields.
 */
@Component
public final class ZoneStore {

    private final AtomicReference<Zone> current = new AtomicReference<>();

    public Optional<Zone> current() {
        return Optional.ofNullable(current.get());
    }

    /** Atomically replaces the snapshot. */
    public void replace(Zone zone) {
        current.set(zone);
    }
}
