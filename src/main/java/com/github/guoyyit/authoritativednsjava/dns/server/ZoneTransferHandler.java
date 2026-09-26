package com.github.guoyyit.authoritativednsjava.dns.server;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsHeader;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RCode;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Optional;

/**
 * Authenticated AXFR. One snapshot is captured before authorization and the
 * whole transfer is built from that single immutable snapshot, so concurrent
 * updates can never produce a mixed old/new view. Unauthorized requests get
 * REFUSED and are audited.
 */
@Component
public class ZoneTransferHandler {

    private final DnsServerConfig config;
    private final ZoneStore store;
    private final AuditLog audit;

    public ZoneTransferHandler(DnsServerConfig config, ZoneStore store, AuditLog audit) {
        this.config = config;
        this.store = store;
        this.audit = audit;
    }

    public DnsMessage handle(DnsMessage query, String presentedKey) {
        DnsMessage resp = newResponse(query);
        DnsHeader h = resp.getHeader();

        Optional<Zone> snapshot = store.current();
        if (snapshot.isEmpty()) {
            h.setRcode(RCode.SERVFAIL);
            audit.record("AXFR", actor(presentedKey), "no-zone", false);
            return resp;
        }

        if (!keyMatches(config.getTransferKey(), presentedKey)) {
            h.setRcode(RCode.REFUSED);
            audit.record("AXFR", actor(presentedKey),
                    "zone=" + snapshot.get().getOrigin() + " reason=bad-key", false);
            return resp;
        }

        Zone zone = snapshot.get(); // single consistent snapshot for the whole transfer
        List<DnsRecord> answers = resp.getAnswers();
        answers.add(zone.getSoa());
        for (DnsRecord r : zone.allRecords()) {
            answers.add(r);
        }
        answers.add(zone.getSoa());
        h.setAa(true);
        h.setRcode(RCode.NOERROR);
        audit.record("AXFR", actor(presentedKey),
                "zone=" + zone.getOrigin() + " records=" + (answers.size() - 2), true);
        return resp;
    }

    /** Constant-time comparison to avoid leaking the key via timing. */
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

    private DnsMessage newResponse(DnsMessage query) {
        DnsMessage resp = new DnsMessage();
        DnsHeader src = query.getHeader();
        DnsHeader dst = resp.getHeader();
        dst.setId(src.getId());
        dst.setQr(true);
        dst.setOpcode(src.getOpcode());
        dst.setRd(src.isRd());
        dst.setRa(true);
        if (!query.getQuestions().isEmpty()) {
            resp.getQuestions().add(query.getQuestions().get(0));
        }
        return resp;
    }
}
