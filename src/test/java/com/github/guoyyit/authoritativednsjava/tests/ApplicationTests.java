package com.github.guoyyit.authoritativednsjava.tests;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

/** Boots the full context: persistence recovery, HTTP API and UDP/TCP listeners. */
@SpringBootTest(properties = {
        "server.port=0",
        "dns.udp-port=0",
        "dns.tcp-port=0",
        "dns.data-dir=target/test-data/application-context"
})
public class ApplicationTests {
    @Test
    public void contentLoad() {
    }
}
