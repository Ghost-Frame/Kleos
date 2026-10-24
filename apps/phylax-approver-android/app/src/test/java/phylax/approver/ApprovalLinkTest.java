package phylax.approver;

/** Dependency-free host-side tests for verified approval links. */
public final class ApprovalLinkTest {
    /** Canonical deterministic pickup handle. */
    private static final String PICKUP = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    /** Approval host the test build is pinned to. */
    private static final String HOST = "approve.example.com";

    /** Run the strict approval-link contract checks. */
    public static void main(String[] args) {
        assertEquals(
                PICKUP,
                ApprovalLink.extractPickup(
                        "https://approve.example.com/v1/phone/open/" + PICKUP, HOST));
        assertEquals(
                PICKUP,
                ApprovalLink.extractPickup(
                        "https://approve.example.com:443/v1/phone/open/" + PICKUP, HOST));
        for (String value : new String[] {
                "phylax://approval?pickup=" + PICKUP,
                "http://approve.example.com/v1/phone/open/" + PICKUP,
                "https://evilapprove.example.com/v1/phone/open/" + PICKUP,
                "https://approve.example.com.evil.example/v1/phone/open/" + PICKUP,
                "https://user@approve.example.com/v1/phone/open/" + PICKUP,
                "https://approve.example.com:8443/v1/phone/open/" + PICKUP,
                "https://approve.example.com/v1/phone/open/" + PICKUP + "/extra",
                "https://approve.example.com/v1/phone/open/%2F" + PICKUP,
                "https://approve.example.com/v1/phone/open/" + PICKUP + "?next=evil",
                "https://approve.example.com/v1/phone/open/" + PICKUP + "#fragment"
        }) {
            assertEquals(null, ApprovalLink.extractPickup(value, HOST));
        }
    }

    /** Fail the host-side test when two values differ. */
    private static void assertEquals(String expected, String actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("expected " + expected + " but got " + actual);
        }
    }
}
