package org.bughunter.burp;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

final class ObservationJson {
    record Header(String name, String value) { }
    record Request(String method, String url, String httpVersion, List<Header> headers, byte[] body) { }
    record Response(int statusCode, String httpVersion, List<Header> headers, byte[] body) { }

    private ObservationJson() { }

    static byte[] encode(String captureId, String event, String listener, Instant at,
                         Request request, Response response, int maxBytes) {
        if (request == null || (!event.equals("REQUEST") && !event.equals("RESPONSE"))
                || (event.equals("RESPONSE") != (response != null))) {
            throw new IllegalArgumentException("Invalid capture event");
        }
        StringBuilder json = new StringBuilder(512);
        json.append("{\"schema\":1,\"capture_id\":");
        string(json, captureId);
        json.append(",\"event\":");
        string(json, event);
        json.append(",\"listener\":");
        string(json, listener);
        json.append(",\"at\":");
        string(json, at.toString());
        json.append(",\"bridge_version\":\"1.0\",\"request\":{");
        json.append("\"method\":");
        string(json, request.method());
        json.append(",\"url\":");
        string(json, request.url());
        json.append(",\"http_version\":");
        string(json, request.httpVersion());
        json.append(",\"headers\":");
        headers(json, request.headers());
        json.append(",\"body_b64\":");
        body(json, request.body());
        json.append('}');
        if (response != null) {
            json.append(",\"response\":{\"status_code\":").append(response.statusCode());
            json.append(",\"http_version\":");
            string(json, response.httpVersion());
            json.append(",\"headers\":");
            headers(json, response.headers());
            json.append(",\"body_b64\":");
            body(json, response.body());
            json.append('}');
        }
        json.append('}');
        byte[] result = json.toString().getBytes(StandardCharsets.UTF_8);
        return result.length <= maxBytes ? result : null;
    }

    private static void body(StringBuilder json, byte[] bytes) {
        if (bytes == null) {
            json.append("null");
        } else {
            string(json, Base64.getEncoder().encodeToString(bytes));
        }
    }

    private static void headers(StringBuilder json, List<Header> headers) {
        json.append('[');
        for (int index = 0; index < headers.size(); index++) {
            if (index > 0) {
                json.append(',');
            }
            json.append('[');
            string(json, headers.get(index).name());
            json.append(',');
            string(json, headers.get(index).value());
            json.append(']');
        }
        json.append(']');
    }

    private static void string(StringBuilder json, String value) {
        if (value == null) {
            json.append("null");
            return;
        }
        json.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> json.append("\\\"");
                case '\\' -> json.append("\\\\");
                case '\n' -> json.append("\\n");
                case '\r' -> json.append("\\r");
                case '\t' -> json.append("\\t");
                default -> {
                    if (character < 0x20) {
                        json.append(String.format("\\u%04x", (int) character));
                    } else {
                        json.append(character);
                    }
                }
            }
        }
        json.append('"');
    }
}
