package phylax.approver;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Rebuilds the phylaxd request digest from the fields the phone displays. */
public final class RequestDigestEncoder {
    /** Domain separator matching the Rust request digest domain. */
    private static final byte[] DOMAIN = "phylax-approval-request-v2\0"
            .getBytes(StandardCharsets.US_ASCII);

    /** Maximum accepted UTF-8 length for any length-prefixed field. */
    private static final int MAX_FIELD_BYTES = 16 * 1024;

    /** Utility-only encoder cannot be instantiated. */
    private RequestDigestEncoder() {}

    /** Encode the pre-hash request digest bytes in the protocol-defined order. */
    public static byte[] encode(
            long version,
            long approvalId,
            String agent,
            String category,
            String target,
            String action,
            long expiresAt,
            byte[] hidden) {
        if (version != 1L || approvalId <= 0L) {
            throw new IllegalArgumentException("unsupported approval identity");
        }
        if (hidden == null || hidden.length != 32) {
            throw new IllegalArgumentException("hidden digest must be 32 bytes");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream(256);
        output.writeBytes(DOMAIN);
        output.writeBytes(longBytes(version));
        output.writeBytes(longBytes(approvalId));
        appendField(output, agent);
        appendField(output, category);
        appendField(output, target);
        appendField(output, action);
        output.writeBytes(longBytes(expiresAt));
        output.writeBytes(hidden);
        return output.toByteArray();
    }

    /** Compute the SHA-256 request digest the phone expects phylaxd to have bound. */
    public static byte[] digest(
            long version,
            long approvalId,
            String agent,
            String category,
            String target,
            String action,
            long expiresAt,
            byte[] hidden) {
        byte[] encoded = encode(
                version, approvalId, agent, category, target, action, expiresAt, hidden);
        try {
            return MessageDigest.getInstance("SHA-256").digest(encoded);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Append one UTF-8 string with a big-endian 32-bit length prefix. */
    private static void appendField(ByteArrayOutputStream output, String value) {
        if (value == null) {
            throw new IllegalArgumentException("missing display field");
        }
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_FIELD_BYTES) {
            throw new IllegalArgumentException("display field too long");
        }
        output.writeBytes(ByteBuffer.allocate(Integer.BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(bytes.length)
                .array());
        output.writeBytes(bytes);
    }

    /** Encode one signed 64-bit value in network byte order. */
    private static byte[] longBytes(long value) {
        return ByteBuffer.allocate(Long.BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(value)
                .array();
    }
}
