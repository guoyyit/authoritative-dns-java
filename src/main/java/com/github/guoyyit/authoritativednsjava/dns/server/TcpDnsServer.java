package com.github.guoyyit.authoritativednsjava.dns.server;

import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsHeader;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessage;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsMessageCodec;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsName;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsParseException;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecord;
import com.github.guoyyit.authoritativednsjava.dns.protocol.DnsRecordType;
import com.github.guoyyit.authoritativednsjava.dns.protocol.RCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * TCP listener with two-byte length-prefixed framing (RFC 1035 §4.2.2).
 * Each connection may carry several sequential queries; AXFR queries are
 * dispatched to the authenticated transfer handler.
 */
public class TcpDnsServer {

    private static final Logger log = LoggerFactory.getLogger(TcpDnsServer.class);
    static final DnsName KEY_OWNER = DnsName.of("key.");
    private static final int MAX_MESSAGE = 65535;

    private final DnsServerConfig config;
    private final QueryHandler queryHandler;
    private final ZoneTransferHandler transferHandler;
    private final ExecutorService workers = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "dns-tcp-worker");
        t.setDaemon(true);
        return t;
    });

    private ServerSocket serverSocket;
    private Thread acceptor;
    private volatile boolean running;

    public TcpDnsServer(DnsServerConfig config, QueryHandler queryHandler,
                        ZoneTransferHandler transferHandler) {
        this.config = config;
        this.queryHandler = queryHandler;
        this.transferHandler = transferHandler;
    }

    public void start() throws Exception {
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(config.getListenAddress(), config.getTcpPort()));
        running = true;
        acceptor = new Thread(this::acceptLoop, "dns-tcp-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();
        log.info("DNS TCP listener on {}:{}", config.getListenAddress(), config.getTcpPort());
    }

    public void stop() {
        running = false;
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
        }
        workers.shutdownNow();
        try {
            workers.awaitTermination(1, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                workers.submit(() -> serve(socket));
            } catch (IOException e) {
                if (running) {
                    log.warn("TCP accept failed: {}", e.toString());
                }
            }
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            socket.setSoTimeout(10_000);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            while (running) {
                int length;
                try {
                    length = in.readUnsignedShort();
                } catch (EOFException e) {
                    return; // clean close by client
                } catch (SocketTimeoutException e) {
                    return;
                }
                if (length == 0) {
                    return;
                }
                if (length > MAX_MESSAGE) {
                    return;
                }
                byte[] request = new byte[length];
                in.readFully(request);
                byte[] response = dispatch(request);
                out.writeShort(response.length);
                out.write(response);
                out.flush();
            }
        } catch (Exception e) {
            log.debug("TCP connection ended: {}", e.toString());
        }
    }

    byte[] dispatch(byte[] request) {
        try {
            DnsMessage query = DnsMessageCodec.decode(request);
            DnsMessage response;
            if (!query.getQuestions().isEmpty()
                    && query.getQuestions().get(0).type() == DnsRecordType.AXFR) {
                response = transferHandler.handle(query, extractKey(query));
            } else {
                response = queryHandler.handle(query);
            }
            return DnsMessageCodec.encode(response);
        } catch (DnsParseException e) {
            return simpleError(request, RCode.FORMERR);
        } catch (Exception e) {
            log.warn("TCP query handling failed: {}", e.toString());
            return simpleError(request, RCode.SERVFAIL);
        }
    }

    /** Key is presented as a TXT RR named "key." in the additional section. */
    static String extractKey(DnsMessage query) {
        for (DnsRecord r : query.getAdditionals()) {
            if (r.getType() == DnsRecordType.TXT && r.getName().equals(KEY_OWNER)) {
                return txtValue(r.getRdata());
            }
        }
        return null;
    }

    private static String txtValue(byte[] rdata) {
        StringBuilder sb = new StringBuilder();
        int p = 0;
        while (p < rdata.length) {
            int len = rdata[p++] & 0xFF;
            sb.append(new String(rdata, p, Math.min(len, rdata.length - p), StandardCharsets.UTF_8));
            p += len;
        }
        return sb.toString();
    }

    private byte[] simpleError(byte[] request, RCode rcode) {
        DnsMessage resp = new DnsMessage();
        DnsHeader h = resp.getHeader();
        int id = 0;
        if (request != null && request.length >= 2) {
            id = ((request[0] & 0xFF) << 8) | (request[1] & 0xFF);
        }
        h.setId(id);
        h.setQr(true);
        h.setRcode(rcode);
        return DnsMessageCodec.encode(resp);
    }
}
