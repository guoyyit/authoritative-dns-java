package com.github.guoyyit.authoritativednsjava.tests;

import com.github.guoyyit.authoritativednsjava.dns.audit.AuditLog;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RData;
import com.github.guoyyit.authoritativednsjava.dns.server.DnsServerConfig;
import com.github.guoyyit.authoritativednsjava.dns.server.QueryHandler;
import com.github.guoyyit.authoritativednsjava.dns.update.ZoneAdminController;
import com.github.guoyyit.authoritativednsjava.dns.update.ZoneUpdateService;
import com.github.guoyyit.authoritativednsjava.dns.zone.Zone;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import com.github.guoyyit.authoritativednsjava.dns.zone.ZoneStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Admin REST API: authenticated hot update takes effect live; bad key is 403 + audited. */
class ZoneAdminControllerTest {

    private static final int IN = 1;
    private static final String KEY = "admin-key";

    @TempDir
    Path dir;
    private MockMvc mvc;
    private ZoneStore store;
    private Path auditFile;
    private ZoneUpdateService svc;

    @BeforeEach
    void setUp() throws Exception {
        DnsServerConfig cfg = new DnsServerConfig();
        cfg.setUpdateKey(KEY);
        store = new ZoneStore();
        DnsName origin = DnsName.of("api.test.");
        Zone seed = Zone.builder(origin)
                .add(new DnsRecord(origin, DnsRecordType.SOA, IN, 60,
                        RData.soaRdata(DnsName.of("ns.api.test."), DnsName.of("hm.api.test."),
                                1, 7200, 3600, 100, 60)))
                .build();
        ZonePersistence persistence = new ZonePersistence(dir.resolve("zone.dat"));
        persistence.save(seed);
        store.replace(seed);
        auditFile = dir.resolve("audit.log");
        AuditLog audit = new AuditLog();
        audit.setFile(auditFile);
        svc = new ZoneUpdateService(cfg, store, persistence, audit);
        mvc = MockMvcBuilders.standaloneSetup(new ZoneAdminController(svc, store)).build();
    }

    @Test
    void hotAddIsImmediatelyVisibleToQueries() throws Exception {
        QueryHandler qh = new QueryHandler(store);
        String body = """
                {"add":[{"name":"new.api.test.","type":"A","ttl":60,"rdata":"192.0.2.77"}],
                 "remove":[]}
                """;
        mvc.perform(post("/zones/records")
                        .header("X-Update-Key", KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("updated"));

        var q = new com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage();
        q.getHeader().setId(1);
        q.getQuestions().add(new com.github.guoyyit.authoritativednsjava.dns.protocol.DnsQuestion(
                DnsName.of("new.api.test."), DnsRecordType.A, IN));
        var resp = qh.handle(q);
        org.junit.jupiter.api.Assertions.assertEquals(1, resp.getAnswers().size());
    }

    @Test
    void missingKeyIsForbiddenAndAudited() throws Exception {
        String body = """
                {"add":[{"name":"x.api.test.","type":"A","ttl":60,"rdata":"192.0.2.8"}],"remove":[]}
                """;
        mvc.perform(post("/zones/records")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("unauthorized"));

        String audit = Files.readString(auditFile);
        org.junit.jupiter.api.Assertions.assertTrue(audit.contains("action=UPDATE"));
        org.junit.jupiter.api.Assertions.assertTrue(audit.contains("result=DENIED"));
    }

    @Test
    void describeReflectsLoadedZone() throws Exception {
        mvc.perform(get("/zones"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.loaded").value(true))
                .andExpect(jsonPath("$.origin").value("api.test."));
    }
}
