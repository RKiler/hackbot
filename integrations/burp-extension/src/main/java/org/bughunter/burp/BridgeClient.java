package org.bughunter.burp;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

final class BridgeClient implements AutoCloseable {
    private final URI base;
    private final String token;
    private final Set<String> listeners;
    private final int maxBytes;
    private final ArrayBlockingQueue<byte[]> queue;
    private final AtomicLong dropped = new AtomicLong();
    private final Thread sender;
    private volatile boolean closed;

    BridgeClient(URI base, String token, Set<String> listeners, int maxBytes, int queueCapacity) {
        if (base == null || !"http".equals(base.getScheme()) || !"127.0.0.1".equals(base.getHost())
                || base.getPort() < 1024 || base.getPort() > 65535
                || !"".equals(base.getPath()) && !"/".equals(base.getPath())
                || base.getRawQuery() != null || base.getRawFragment() != null || base.getRawUserInfo() != null
                || token == null || !token.matches("[A-Za-z0-9._~-]{32,256}")
                || listeners == null || listeners.isEmpty()
                || maxBytes < 4096 || maxBytes > 8_388_608
                || queueCapacity < 1 || queueCapacity > 1024) {
            throw new IllegalArgumentException("Invalid local bridge configuration");
        }
        for (String listener : listeners) {
            if (!listener.matches("127\\.0\\.0\\.1:[0-9]{4,5}")) {
                throw new IllegalArgumentException("Invalid local listener configuration");
            }
        }
        this.base = base;
        this.token = token;
        this.listeners = Set.copyOf(listeners);
        this.maxBytes = maxBytes;
        this.queue = new ArrayBlockingQueue<>(queueCapacity);
        this.sender = new Thread(this::run, "hackbot-burp-bridge-sender");
        this.sender.setDaemon(true);
        this.sender.start();
    }

    static BridgeClient fromEnvironment() {
        String address = System.getenv("HACKBOT_BURP_BRIDGE_URL");
        String token = System.getenv("HACKBOT_SECRET_BURP_BRIDGE");
        String rawListeners = System.getenv("HACKBOT_BURP_LISTENERS");
        if (address == null || rawListeners == null) {
            throw new IllegalArgumentException("Local bridge configuration is missing");
        }
        Set<String> listeners = new HashSet<>(Arrays.asList(rawListeners.split(",", -1)));
        try {
            return new BridgeClient(URI.create(address), token, listeners, 1_048_576, 64);
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException("Invalid local bridge configuration");
        }
    }

    boolean accepts(String listener) {
        return listeners.contains(listener);
    }

    int maxBytes() {
        return maxBytes;
    }

    boolean submit(byte[] payload) {
        if (closed || payload == null || payload.length > maxBytes || !queue.offer(payload)) {
            dropped.incrementAndGet();
            return false;
        }
        return true;
    }

    long droppedCount() {
        return dropped.get();
    }

    private void run() {
        heartbeat();
        while (!closed) {
            try {
                byte[] payload = queue.poll(30, TimeUnit.SECONDS);
                if (payload == null) {
                    heartbeat();
                } else {
                    int status = transmit("/v1/capture", payload);
                    if (status == 503 || status == 429 || status == -1) {
                        status = transmit("/v1/capture", payload);
                    }
                    if (status != 200 && status != 201) {
                        dropped.incrementAndGet();
                    }
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void heartbeat() {
        byte[] payload = ("{\"version\":\"1.0\",\"dropped_events\":" + dropped.get() + "}")
                .getBytes(StandardCharsets.UTF_8);
        transmit("/v1/heartbeat", payload);
    }

    private int transmit(String path, byte[] payload) {
        HttpURLConnection connection = null;
        try {
            URI destination = base.resolve(path);
            connection = (HttpURLConnection) destination.toURL().openConnection(Proxy.NO_PROXY);
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(1000);
            connection.setReadTimeout(3000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("X-Hackbot-Bridge-Token", token);
            connection.setFixedLengthStreamingMode(payload.length);
            try (var output = connection.getOutputStream()) {
                output.write(payload);
            }
            return connection.getResponseCode();
        } catch (IOException failure) {
            return -1;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    @Override
    public void close() {
        closed = true;
        sender.interrupt();
        queue.clear();
    }
}
