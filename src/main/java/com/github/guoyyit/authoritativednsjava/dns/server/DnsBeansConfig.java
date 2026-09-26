package com.github.guoyyit.authoritativednsjava.dns.server;

import com.github.guoyyit.authoritativednsjava.dns.zone.ZonePersistence;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Paths;

/** Shared infrastructure beans (single persistence instance for recovery and updates). */
@Configuration
public class DnsBeansConfig {

    @Bean
    public ZonePersistence zonePersistence(DnsServerConfig config) {
        return new ZonePersistence(
                Paths.get(config.getDataDir()).resolve(config.getZoneFile()));
    }
}
