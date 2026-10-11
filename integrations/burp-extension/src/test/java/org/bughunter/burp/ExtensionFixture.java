package org.bughunter.burp;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Set;

public final class ExtensionFixture {
    public static void main(String[] args) {
        assert !CaptureIds.forMessage("fixture", "127.0.0.1:38080", 42).equals(
                CaptureIds.forMessage("fixture", "127.0.0.1:38081", 42));
        var request = new ObservationJson.Request("GET", "https://app.example.test/fixture",
                "HTTP/1.1", List.of(new ObservationJson.Header("Accept", "application/json")),
                new byte[0]);
        var response = new ObservationJson.Response(200, "HTTP/1.1",
                List.of(new ObservationJson.Header("Content-Type", "text/plain")),
                "fixture".getBytes(StandardCharsets.UTF_8));
        String captureId = CaptureIds.forMessage(
                "019dec18-d5e9-7e93-a999-95f4fecd3891", "127.0.0.1:38080", 42);
        byte[] payload = ObservationJson.encode(captureId, "RESPONSE", "127.0.0.1:38080",
                Instant.parse("2026-10-10T00:00:00Z"), request, response, 4096);
        assert payload != null;
        assert ObservationJson.encode(captureId, "RESPONSE", "127.0.0.1:38080",
                Instant.now(), request, response, 16) == null;
        assert new String(payload, StandardCharsets.UTF_8).contains("\"schema\":1");
        try (var client = new BridgeClient(URI.create("http://127.0.0.1:38777"),
                "fixture-bridge-token-with-at-least-32-characters",
                Set.of("127.0.0.1:38080"), 4096, 1)) {
            assert client.accepts("127.0.0.1:38080");
            assert !client.accepts("127.0.0.1:38081");
            assert !client.submit(new byte[4097]);
            assert client.droppedCount() == 1;
        }
        System.out.println(new String(payload, StandardCharsets.UTF_8));
    }
}
