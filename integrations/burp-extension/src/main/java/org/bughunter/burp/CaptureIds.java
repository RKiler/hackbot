package org.bughunter.burp;

final class CaptureIds {
    private CaptureIds() { }

    static String forMessage(String instanceId, String listener, int messageId) {
        return instanceId + ":" + listener + ":" + messageId;
    }
}
