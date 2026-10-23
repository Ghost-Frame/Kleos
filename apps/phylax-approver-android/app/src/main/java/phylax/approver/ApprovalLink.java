package phylax.approver;

import java.net.URI;

/** Parses only the verified HTTPS approval-link contract. */
public final class ApprovalLink {
    /** Exact path prefix routed into the native approver. */
    private static final String APPROVAL_PATH_PREFIX = "/v1/phone/open/";

    /** Prevent construction of this protocol utility. */
    private ApprovalLink() {
    }

    /** Return one canonical pickup handle or null for every non-contract URI. */
    public static String extractPickup(String rawUri, String approvalHost) {
        if (rawUri == null || rawUri.isEmpty()
                || approvalHost == null || approvalHost.isEmpty()) {
            return null;
        }
        final URI uri;
        try {
            uri = URI.create(rawUri);
        } catch (IllegalArgumentException error) {
            return null;
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null
                || !approvalHost.equalsIgnoreCase(uri.getHost())
                || uri.getRawUserInfo() != null
                || (uri.getPort() != -1 && uri.getPort() != 443)
                || uri.getRawQuery() != null
                || uri.getRawFragment() != null) {
            return null;
        }
        String rawPath = uri.getRawPath();
        if (rawPath == null || !rawPath.startsWith(APPROVAL_PATH_PREFIX)) {
            return null;
        }
        String pickup = rawPath.substring(APPROVAL_PATH_PREFIX.length());
        return pickup.matches("[A-Za-z0-9_-]{43}") ? pickup : null;
    }
}
