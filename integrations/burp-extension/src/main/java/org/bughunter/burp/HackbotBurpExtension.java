package org.bughunter.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class HackbotBurpExtension implements BurpExtension, ProxyRequestHandler, ProxyResponseHandler {
    private static final int MAX_PENDING_REQUESTS = 128;
    private record PendingKey(String listener, int messageId) { }

    private final String instanceId = UUID.randomUUID().toString();
    private final Map<PendingKey, ObservationJson.Request> pending = new LinkedHashMap<>();
    private BridgeClient bridge;

    @Override
    public void initialize(MontoyaApi api) {
        bridge = BridgeClient.fromEnvironment();
        api.extension().setName("BugHunter Capture Bridge");
        api.proxy().registerRequestHandler(this);
        api.proxy().registerResponseHandler(this);
        api.extension().registerUnloadingHandler(bridge::close);
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest request) {
        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest request) {
        if (bridge.accepts(request.listenerInterface())) {
            ObservationJson.Request snapshot = snapshot(request, bridge.maxBytes() / 4);
            synchronized (pending) {
                if (pending.size() >= MAX_PENDING_REQUESTS) {
                    pending.remove(pending.keySet().iterator().next());
                }
                pending.put(new PendingKey(request.listenerInterface(), request.messageId()), snapshot);
            }
            byte[] payload = ObservationJson.encode(captureId(request.listenerInterface(), request.messageId()), "REQUEST",
                    request.listenerInterface(), Instant.now(), snapshot, null, bridge.maxBytes());
            bridge.submit(payload);
        }
        return ProxyRequestToBeSentAction.continueWith(request);
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
        return ProxyResponseReceivedAction.continueWith(response);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
        if (bridge.accepts(response.listenerInterface())) {
            ObservationJson.Request request;
            synchronized (pending) {
                request = pending.remove(new PendingKey(response.listenerInterface(), response.messageId()));
            }
            if (request == null) {
                request = snapshot(response.initiatingRequest(), bridge.maxBytes() / 4);
            }
            var captured = new ObservationJson.Response(response.statusCode(), response.httpVersion(),
                    headers(response.headers()), body(response.body(), bridge.maxBytes() / 2));
            byte[] payload = ObservationJson.encode(captureId(response.listenerInterface(), response.messageId()), "RESPONSE",
                    response.listenerInterface(), Instant.now(), request, captured, bridge.maxBytes());
            bridge.submit(payload);
        }
        return ProxyResponseToBeSentAction.continueWith(response);
    }

    private String captureId(String listener, int messageId) {
        return CaptureIds.forMessage(instanceId, listener, messageId);
    }

    private static ObservationJson.Request snapshot(HttpRequest request, int bodyLimit) {
        return new ObservationJson.Request(request.method(), request.url(), request.httpVersion(),
                headers(request.headers()), body(request.body(), bodyLimit));
    }

    private static byte[] body(burp.api.montoya.core.ByteArray source, int limit) {
        return source.length() <= limit ? source.getBytes() : null;
    }

    private static List<ObservationJson.Header> headers(List<HttpHeader> source) {
        List<ObservationJson.Header> result = new ArrayList<>(source.size());
        for (HttpHeader header : source) {
            result.add(new ObservationJson.Header(header.name(), header.value()));
        }
        return result;
    }
}
