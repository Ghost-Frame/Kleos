package phylax.approver;

import java.util.Arrays;
import java.util.HexFormat;

/** Host-side golden-vector tests for the Rust-compatible signed encoding. */
public final class CanonicalApprovalEncoderTest {
    /** Utility-only test class cannot be instantiated. */
    private CanonicalApprovalEncoderTest() {}

    /** Runs every dependency-free host-side protocol test. */
    public static void main(String[] args) {
        goldenVectorMatchesRustProtocol();
        changedDecisionChangesMessage();
        invalidNonceLengthFailsClosed();
    }

    /** Proves Java emits the exact byte sequence pinned by the Rust verifier. */
    private static void goldenVectorMatchesRustProtocol() {
        byte[] nonce = new byte[32];
        byte[] digest = new byte[32];
        Arrays.fill(nonce, (byte) 0x31);
        Arrays.fill(digest, (byte) 0x77);

        byte[] actual = CanonicalApprovalEncoder.encode(
                1L,
                42L,
                nonce,
                digest,
                CanonicalApprovalEncoder.APPROVED,
                "phone-primary",
                1_786_820_100L,
                1_786_820_900L);

        String expected = "7068796c61782d70686f6e652d617070726f76616c2d763100"
                + "0000000000000001000000000000002a"
                + "3131313131313131313131313131313131313131313131313131313131313131"
                + "7777777777777777777777777777777777777777777777777777777777777777"
                + "010000000d70686f6e652d7072696d617279"
                + "000000006a80b604000000006a80b924";
        require(expected.equals(HexFormat.of().formatHex(actual)), "golden vector mismatch");
    }

    /** Proves the decision byte is part of the signature input. */
    private static void changedDecisionChangesMessage() {
        byte[] nonce = new byte[32];
        byte[] digest = new byte[32];
        byte[] approved = CanonicalApprovalEncoder.encode(
                1L, 1L, nonce, digest, CanonicalApprovalEncoder.APPROVED,
                "phone", 10L, 20L);
        byte[] denied = CanonicalApprovalEncoder.encode(
                1L, 1L, nonce, digest, CanonicalApprovalEncoder.DENIED,
                "phone", 10L, 20L);
        require(!Arrays.equals(approved, denied), "decision mutation was not bound");
    }

    /** Proves malformed server nonces are rejected before signing. */
    private static void invalidNonceLengthFailsClosed() {
        try {
            CanonicalApprovalEncoder.encode(
                    1L, 1L, new byte[31], new byte[32],
                    CanonicalApprovalEncoder.APPROVED, "phone", 10L, 20L);
            throw new AssertionError("short nonce was accepted");
        } catch (IllegalArgumentException expected) {
            require(true, "expected rejection");
        }
    }

    /** Throws an assertion error when a protocol invariant does not hold. */
    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
