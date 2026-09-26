package com.github.guoyyit.authoritativednsjava.dns.server;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsHeader;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessageCodec;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsParseException;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * UDP listener. A response larger than the configured UDP payload limit is
 * truncated (only header + question retained, TC bit set) so the client
 * retries over TCP and gets the full response.
 */
public class UdpDnsServer {

    private static final Logger log = LoggerFactory.getLogger(UdpDnsServer.class);
    private static final int RECV_BUFFER = 65535;

    private final DnsServerConfig config;
    private final QueryHandler queryHandler;
    private final ExecutorService workers = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "dns-udp-worker");
        t.setDaemon(true);
        return t;
    });

    private DatagramSocket socket;
    private Thread acceptor;
    private volatile boolean running;

    public UdpDnsServer(DnsServerConfig config, QueryHandler queryHandler) {
        this.config = config;
        this.queryHandler = queryHandler;
    }

    public void start() throws Exception {
        socket = new DatagramSocket(
                new InetSocketAddress(config.getListenAddress(), config.getUdpPort()));
        running = true;
        acceptor = new Thread(this::acceptLoop, "dns-udp-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();
        log.info("DNS UDP listener on {}:{}", config.getListenAddress(), config.getUdpPort());
    }

    public void stop() {
        running = false;
        if (socket != null) {
            socket.close();
        }
        workers.shutdownNow();
        try {
            workers.awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void acceptLoop() {
        byte[] buf = new byte[RECV_BUFFER];
        while (running) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            try {
                socket.receive(packet);
            } catch (Exception e) {
                if (running) {
                    log.warn("UDP receive failed: {}", e.toString());
                }
                continue;
            }
            byte[] copy = new byte[packet.getLength()];
            System.arraycopy(packet.getData(), packet.getOffset(), copy, 0, packet.getLength());
            InetSocketAddress client = (InetSocketAddress) packet.getSocketAddress();
            workers.submit(() -> process(copy, client));
        }
    }

    private void process(byte[] requestBytes, InetSocketAddress client) {
        byte[] responseBytes;
        try {
            DnsMessage query = DnsMessageCodec.decode(requestBytes);
            DnsMessage response;
            if (isAxfr(query)) {
                response = refuse(query); // AXFR is defined for TCP only
            } else {
                response = queryHandler.handle(query);
            }
            responseBytes = DnsMessageCodec.encode(response);
            if (responseBytes.length > config.getUdpMaxPayload()) {
                responseBytes = truncate(response);
            }
        } catch (DnsParseException e) {
            responseBytes = errorResponse(requestBytes, RCode.FORMERR);
        } catch (Exception e) {
            log.warn("UDP query handling failed: {}", e.toString());
            responseBytes = errorResponse(requestBytes, RCode.SERVFAIL);
        }
        try {
            socket.send(new DatagramPacket(responseBytes, responseBytes.length, client));
        } catch (Exception e) {
            log.warn("UDP send failed: {}", e.toString());
        }
    }

    private boolean isAxfr(DnsMessage query) {
        return !query.getQuestions().isEmpty()
                && query.getQuestions().get(0).type() == DnsRecordType.AXFR;
    }

    private byte[] truncate(DnsMessage response) {
        // Retain header + question only; set TC so the client retries over TCP.
        response.getAnswers().clear();
        response.getAuthorities().clear();
        response.getAdditionals().clear();
        DnsHeader h = response.getHeader();
        h.setTc(true);
        h.setAnCount(0);
        h.setNsCount(0);
        h.setArCount(0);
        return DnsMessageCodec.encode(response);
    }

    private DnsMessage refuse(DnsMessage query) {
        DnsMessage resp = new DnsMessage();
        copyHeaderIds(query, resp);
        resp.getHeader().setRcode(RCode.REFUSED);
        if (!query.getQuestions().isEmpty()) {
            resp.getQuestions().add(query.getQuestions().get(0));
        }
        return resp;
    }

    private void copyHeaderIds(DnsMessage query, DnsMessage resp) {
        DnsHeader src = query.getHeader();
        DnsHeader dst = resp.getHeader();
        dst.setId(src.getId());
        dst.setQr(true);
        dst.setOpcode(src.getOpcode());
        dst.setRd(src.isRd());
    }

    private byte[] errorResponse(byte[] requestBytes, RCode rcode) {
        DnsMessage resp = new DnsMessage();
        DnsHeader h = resp.getHeader();
        int id = 0;
        if (requestBytes.length >= 2) {
            id = ((requestBytes[0] & 0xFF) << 8) | (requestBytes[1] & 0xFF);
        }
        h.setId(id);
        h.setQr(true);
        h.setRcode(rcode);
        return DnsMessageCodec.encode(resp);
    }
}
