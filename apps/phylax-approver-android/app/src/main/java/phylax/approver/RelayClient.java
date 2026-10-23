package phylax.approver;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executor;

/** Minimal HTTPS client for the untrusted Phylax phone relay. */
public final class RelayClient {
    /** Maximum relay response size accepted by the app. */
    private static final int MAXIMUM_RESPONSE_BYTES = 65_536;
    /** Pinned build-time relay origin without a trailing slash. */
    private final String baseUrl;
    /** Background executor used for all network operations. */
    private final Executor networkExecutor;

    /** Receives either one approval response or a sanitized error. */
    public interface Callback {
        /** Handle a successful JSON response. */
        void onSuccess(JSONObject response);

        /** Handle a failure without exposing response contents. */
        void onFailure(String message);
    }

    /** Create a client that accepts only a pinned HTTPS origin. */
    public RelayClient(String configuredBaseUrl, String approvalHost, Executor networkExecutor) {
        if (configuredBaseUrl == null || configuredBaseUrl.isEmpty()) {
            throw new IllegalStateException("relay URL is not configured");
        }
        String normalized = configuredBaseUrl.endsWith("/")
                ? configuredBaseUrl.substring(0, configuredBaseUrl.length() - 1)
                : configuredBaseUrl;
        URI parsed = URI.create(normalized);
        if (!"https".equals(parsed.getScheme()) || parsed.getHost() == null
                || parsed.getUserInfo() != null || parsed.getQuery() != null
                || parsed.getFragment() != null || parsed.getPort() != -1
                || approvalHost == null || approvalHost.isEmpty()
                || !("https://" + approvalHost).equals(normalized)) {
            throw new IllegalStateException("relay URL is not the authorized origin");
        }
        this.baseUrl = normalized;
        this.networkExecutor = networkExecutor;
    }

    /** Fetch one pending approval using a random, non-secret pickup handle. */
    public void fetchApproval(String pickupHandle, Callback callback) {
        if (!validPickupHandle(pickupHandle)) {
            callback.onFailure("Invalid approval link");
            return;
        }
        networkExecutor.execute(() -> {
            try {
                callback.onSuccess(request("GET", pickupHandle, null));
            } catch (Exception error) {
                callback.onFailure("Approval could not be loaded");
            }
        });
    }

    /** Submit one signed decision without sending any phone-held secret. */
    public void submitDecision(
            String pickupHandle, JSONObject decision, Callback callback) {
        if (!validPickupHandle(pickupHandle)) {
            callback.onFailure("Invalid approval link");
            return;
        }
        networkExecutor.execute(() -> {
            try {
                callback.onSuccess(request("POST", pickupHandle, decision));
            } catch (Exception error) {
                callback.onFailure("Decision could not be delivered");
            }
        });
    }

    /** Execute one bounded request with redirects disabled. */
    private JSONObject request(String method, String pickupHandle, JSONObject body)
            throws Exception {
        String suffix = body == null ? "" : "/decision";
        URL url = URI.create(baseUrl + "/v1/phone/requests/" + pickupHandle + suffix).toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(5_000);
        connection.setReadTimeout(10_000);
        connection.setRequestMethod(method);
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("Cache-Control", "no-store");
        if (body != null) {
            byte[] encoded = body.toString().getBytes(StandardCharsets.UTF_8);
            connection.setDoOutput(true);
            connection.setFixedLengthStreamingMode(encoded.length);
            connection.setRequestProperty("Content-Type", "application/json");
            try (OutputStream output = connection.getOutputStream()) {
                output.write(encoded);
            }
        }
        int status = connection.getResponseCode();
        if (status < 200 || status >= 300) {
            connection.disconnect();
            throw new IllegalStateException("relay rejected request");
        }
        try (InputStream input = connection.getInputStream()) {
            byte[] response = readBounded(input);
            return new JSONObject(new String(response, StandardCharsets.UTF_8));
        } finally {
            connection.disconnect();
        }
    }

    /** Read at most the protocol response limit. */
    private static byte[] readBounded(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4_096];
        int count;
        while ((count = input.read(buffer)) != -1) {
            if (output.size() + count > MAXIMUM_RESPONSE_BYTES) {
                throw new IllegalStateException("relay response is too large");
            }
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    /** Accept only the relay's fixed-format 256-bit pickup handle. */
    private static boolean validPickupHandle(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{43}");
    }
}
