package com.github.guoyyit.authoritativednsjava.dns.update;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistenceException;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** REST management endpoint for zone creation and record updates. */
@RestController
@RequestMapping("/zones")
public class ZoneAdminController {

    private static final int CLASS_IN = 1;

    private final ZoneUpdateService updateService;
    private final ZoneStore store;

    public ZoneAdminController(ZoneUpdateService updateService, ZoneStore store) {
        this.updateService = updateService;
        this.store = store;
    }

    public record RecordDto(String name, String type, long ttl, String rdata) {
    }

    public record UpdateRequest(List<RecordDto> add, List<RecordDto> remove) {
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> createZone(
            @RequestParam String origin,
            @RequestHeader(value = "X-Update-Key", required = false) String key) {
        try {
            updateService.createZone(origin, key);
            return ResponseEntity.ok(Map.of("status", "created", "origin", origin));
        } catch (AuthorizationException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "unauthorized"));
        } catch (ZonePersistenceException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/records")
    public ResponseEntity<Map<String, Object>> applyUpdate(
            @RequestBody UpdateRequest request,
            @RequestHeader(value = "X-Update-Key", required = false) String key) {
        try {
            updateService.applyUpdate(toRecords(request.add()), toRecords(request.remove()), key);
            return ResponseEntity.ok(Map.of("status", "updated"));
        } catch (AuthorizationException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "unauthorized"));
        } catch (ZonePersistenceException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> describe() {
        Optional<Zone> zone = store.current();
        if (zone.isEmpty()) {
            return ResponseEntity.ok(Map.of("loaded", false));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("loaded", true);
        out.put("origin", zone.get().getOrigin().toString());
        out.put("serial", zone.get().getSerial());
        out.put("records", zone.get().allRecords().size());
        return ResponseEntity.ok(out);
    }

    private static List<DnsRecord> toRecords(List<RecordDto> dtos) {
        List<DnsRecord> out = new ArrayList<>();
        if (dtos == null) {
            return out;
        }
        for (RecordDto dto : dtos) {
            int type = DnsRecordType.parse(dto.type());
            byte[] rdata = RData.fromText(type, dto.rdata());
            out.add(new DnsRecord(DnsName.of(dto.name()), type, CLASS_IN, dto.ttl(), rdata));
        }
        return out;
    }
}
