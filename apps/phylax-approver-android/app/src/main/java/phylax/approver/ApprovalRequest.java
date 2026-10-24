package phylax.approver;

import android.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.MessageDigest;

/** Immutable public metadata for one relay-delivered approval request. */
public final class ApprovalRequest {
    /** Protocol version supplied by phylaxd. */
    public final long version;
    /** Server approval identifier. */
    public final long approvalId;
    /** Base64url server nonce. */
    public final String nonce;
    /** Base64url immutable request digest. */
    public final String requestDigest;
    /** Base64url digest of the request fields this phone does not display. */
    public final String hiddenDigest;
    /** Enrolled device identifier. */
    public final String deviceId;
    /** Phone-visible action name. */
    public final String action;
    /** Phone-visible requesting agent. */
    public final String agentName;
    /** Phone-visible target category. */
    public final String category;
    /** Phone-visible target name. */
    public final String targetName;
    /** Exact server expiry as Unix seconds. */
    public final long expiresAt;

    /** Construct validated approval metadata from explicit fields. */
    private ApprovalRequest(
            long version,
            long approvalId,
            String nonce,
            String requestDigest,
            String hiddenDigest,
            String deviceId,
            String action,
            String agentName,
            String category,
            String targetName,
            long expiresAt) {
        this.version = version;
        this.approvalId = approvalId;
        this.nonce = nonce;
        this.requestDigest = requestDigest;
        this.hiddenDigest = hiddenDigest;
        this.deviceId = deviceId;
        this.action = action;
        this.agentName = agentName;
        this.category = category;
        this.targetName = targetName;
        this.expiresAt = expiresAt;
    }

    /** Parse a relay response and reject malformed or oversized metadata. */
    public static ApprovalRequest fromJson(JSONObject value) throws JSONException {
        ApprovalRequest request = new ApprovalRequest(
                value.getLong("version"),
                value.getLong("approval_id"),
                bounded(value.getString("nonce"), 128),
                bounded(value.getString("request_digest"), 128),
                bounded(value.getString("hidden_digest"), 128),
                bounded(value.getString("device_id"), 128),
                bounded(value.getString("action"), 256),
                bounded(value.getString("agent_name"), 256),
                bounded(value.getString("category"), 256),
                bounded(value.getString("target_name"), 512),
                value.getLong("expires_at"));
        if (request.version != 1L || request.approvalId <= 0L
                || decode32(request.nonce).length != 32
                || decode32(request.requestDigest).length != 32
                || decode32(request.hiddenDigest).length != 32) {
            throw new JSONException("invalid approval request");
        }
        return request;
    }

    /**
     * Recompute the request digest from the displayed fields and the hidden
     * digest, and compare it in constant time to the relay-supplied digest.
     */
    public boolean digestMatches() {
        byte[] recomputed = RequestDigestEncoder.digest(
                version,
                approvalId,
                agentName,
                category,
                targetName,
                action,
                expiresAt,
                decode32(hiddenDigest));
        return MessageDigest.isEqual(recomputed, decode32(requestDigest));
    }

    /** Build the canonical bytes authorized by one biometric operation. */
    public byte[] canonicalMessage(byte decision, long issuedAt) {
        return CanonicalApprovalEncoder.encode(
                version,
                approvalId,
                decode32(nonce),
                decode32(requestDigest),
                decision,
                deviceId,
                issuedAt,
                expiresAt);
    }

    /** Serialize the signed decision submitted through the untrusted relay. */
    public JSONObject signedDecision(byte decision, long issuedAt, byte[] signature)
            throws JSONException {
        String decisionName = decision == CanonicalApprovalEncoder.APPROVED
                ? "approved" : "denied";
        return new JSONObject()
                .put("version", version)
                .put("approval_id", approvalId)
                .put("nonce", nonce)
                .put("request_digest", requestDigest)
                .put("decision", decisionName)
                .put("device_id", deviceId)
                .put("issued_at", issuedAt)
                .put("expires_at", expiresAt)
                .put("signature", Base64.encodeToString(
                        signature, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING));
    }

    /** Decode one unpadded base64url 32-byte protocol field. */
    private static byte[] decode32(String value) {
        byte[] decoded = Base64.decode(value, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
        if (decoded.length != 32) {
            throw new IllegalArgumentException("protocol field must contain 32 bytes");
        }
        return decoded;
    }

    /** Reject empty or oversized relay-controlled display strings. */
    private static String bounded(String value, int maximum) throws JSONException {
        if (value.isEmpty() || value.length() > maximum) {
            throw new JSONException("invalid display field");
        }
        return value;
    }
}
