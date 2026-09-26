package com.github.guoyyit.authoritativednsjava.dns.server;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/** Listen address/ports, data directory and shared keys, all configurable. */
@Component
@ConfigurationProperties(prefix = "dns")
public class DnsServerConfig {
    private String listenAddress = "127.0.0.1";
    private int udpPort = 15353;
    private int tcpPort = 15353;
    private int udpMaxPayload = 512;
    private String dataDir = "data";
    private String zoneFile = "zone.dat";
    private String auditFile = "audit.log";
    private String updateKey = "change-me-update-key";
    private String transferKey = "change-me-transfer-key";

    public String getListenAddress() { return listenAddress; }
    public void setListenAddress(String listenAddress) { this.listenAddress = listenAddress; }
    public int getUdpPort() { return udpPort; }
    public void setUdpPort(int udpPort) { this.udpPort = udpPort; }
    public int getTcpPort() { return tcpPort; }
    public void setTcpPort(int tcpPort) { this.tcpPort = tcpPort; }
    public int getUdpMaxPayload() { return udpMaxPayload; }
    public void setUdpMaxPayload(int udpMaxPayload) { this.udpMaxPayload = udpMaxPayload; }
    public String getDataDir() { return dataDir; }
    public void setDataDir(String dataDir) { this.dataDir = dataDir; }
    public String getZoneFile() { return zoneFile; }
    public void setZoneFile(String zoneFile) { this.zoneFile = zoneFile; }
    public String getAuditFile() { return auditFile; }
    public void setAuditFile(String auditFile) { this.auditFile = auditFile; }
    public String getUpdateKey() { return updateKey; }
    public void setUpdateKey(String updateKey) { this.updateKey = updateKey; }
    public String getTransferKey() { return transferKey; }
    public void setTransferKey(String transferKey) { this.transferKey = transferKey; }
}
