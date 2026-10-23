package phylax.approver;

import java.util.Arrays;
import java.util.HexFormat;

/** Host-side golden-vector tests for the Rust-compatible request digest. */
public final class RequestDigestEncoderTest {
    /** Utility-only test class cannot be instantiated. */
    private RequestDigestEncoderTest() {}

    /** Runs every dependency-free host-side request digest test. */
    public static void main(String[] args) {
        goldenVectorMatchesRustProtocol();
        changedTargetChangesDigest();
    }

    /** Proves Java produces the digest pinned by the Rust golden vector test. */
    private static void goldenVectorMatchesRustProtocol() {
        byte[] hidden = new byte[32];
        Arrays.fill(hidden, (byte) 0x55);

        byte[] actual = RequestDigestEncoder.digest(
                1L, 42L, "codex", "ssh-ca", "build-01", "ssh_ca_sign",
                1_786_820_900L, hidden);

        String expected = "d8709ecce2ae14b2618d78f27630d8ba6f98cef26228ab89d769f66932218bea";
        require(expected.equals(HexFormat.of().formatHex(actual)), "golden vector mismatch");
    }

    /** Proves a changed displayed target changes the recomputed digest. */
    private static void changedTargetChangesDigest() {
        byte[] hidden = new byte[32];
        byte[] first = RequestDigestEncoder.digest(
                1L, 42L, "codex", "ssh-ca", "build-01", "ssh_ca_sign", 20L, hidden);
        byte[] second = RequestDigestEncoder.digest(
                1L, 42L, "codex", "ssh-ca", "build-02", "ssh_ca_sign", 20L, hidden);
        require(!Arrays.equals(first, second), "target mutation was not bound");
    }

    /** Throws an assertion error when a protocol invariant does not hold. */
    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
