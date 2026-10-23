package phylax.approver;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Encodes exact-phone decisions byte-for-byte like the phylaxd Rust verifier. */
public final class CanonicalApprovalEncoder {
    /** Protocol decision byte for approval. */
    public static final byte APPROVED = 1;

    /** Protocol decision byte for denial. */
    public static final byte DENIED = 2;

    /** Domain separator preventing cross-protocol signature reuse. */
    private static final byte[] DOMAIN = "phylax-phone-approval-v1\0"
            .getBytes(StandardCharsets.US_ASCII);

    /** Maximum accepted UTF-8 length for the enrolled device identifier. */
    private static final int MAX_DEVICE_ID_BYTES = 16 * 1024;

    /** Utility-only encoder cannot be instantiated. */
    private CanonicalApprovalEncoder() {}

    /** Encode all signed fields in the protocol-defined order. */
    public static byte[] encode(
            long version,
            long approvalId,
            byte[] nonce,
            byte[] requestDigest,
            byte decision,
            String deviceId,
            long issuedAt,
            long expiresAt) {
        if (version != 1L || approvalId <= 0L) {
            throw new IllegalArgumentException("unsupported approval identity");
        }
        if (nonce == null || nonce.length != 32
                || requestDigest == null || requestDigest.length != 32) {
            throw new IllegalArgumentException("nonce and digest must be 32 bytes");
        }
        if (decision != APPROVED && decision != DENIED) {
            throw new IllegalArgumentException("unsupported decision");
        }
        if (deviceId == null || issuedAt > expiresAt) {
            throw new IllegalArgumentException("invalid signed metadata");
        }
        byte[] deviceBytes = deviceId.getBytes(StandardCharsets.UTF_8);
        if (deviceBytes.length == 0 || deviceBytes.length > MAX_DEVICE_ID_BYTES) {
            throw new IllegalArgumentException("invalid device identifier");
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream(160 + deviceBytes.length);
        put(output, DOMAIN);
        put(output, longBytes(version));
        put(output, longBytes(approvalId));
        put(output, nonce);
        put(output, requestDigest);
        output.write(decision);
        put(output, intBytes(deviceBytes.length));
        put(output, deviceBytes);
        put(output, longBytes(issuedAt));
        put(output, longBytes(expiresAt));
        return output.toByteArray();
    }

    /**
     * Append a whole byte array. ByteArrayOutputStream#writeBytes needs API 33,
     * and minSdk is 31, so this uses the API 1 three-argument write instead.
     */
    private static void put(ByteArrayOutputStream output, byte[] bytes) {
        output.write(bytes, 0, bytes.length);
    }

    /** Encode one signed 64-bit value in network byte order. */
    private static byte[] longBytes(long value) {
        return ByteBuffer.allocate(Long.BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(value)
                .array();
    }

    /** Encode one unsigned-compatible 32-bit length in network byte order. */
    private static byte[] intBytes(int value) {
        return ByteBuffer.allocate(Integer.BYTES)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(value)
                .array();
    }
}
