package phylax.approver;

import android.app.Activity;
import android.content.Intent;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.view.Gravity;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.json.JSONObject;

import java.security.Signature;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Displays one exact-phone approval and signs the decision after strong biometrics. */
public final class MainActivity extends Activity {
    /** Preference file populated by the local hardware enrollment ceremony. */
    private static final String ENROLLMENT_PREFERENCES = "phylax-enrollment";
    /** Preference key containing the server-assigned device identifier. */
    private static final String DEVICE_ID_PREFERENCE = "device-id";
    /** Background executor isolated to relay traffic. */
    private final ExecutorService networkExecutor = Executors.newSingleThreadExecutor();
    /** StrongBox signing facade. */
    private final StrongBoxSigner signer = new StrongBoxSigner();
    /** Main approval detail view. */
    private TextView detailView;
    /** User-visible state view containing no secret material. */
    private TextView statusView;
    /** Approval action button. */
    private Button approveButton;
    /** Denial action button. */
    private Button denyButton;
    /** Relay client created only after validating the build-time origin. */
    private RelayClient relayClient;
    /** Current opaque relay pickup handle. */
    private String pickupHandle;
    /** Current server-bound approval request. */
    private ApprovalRequest approvalRequest;

    /** Build the secure screen and process an incoming approval link. */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        buildInterface();
        try {
            relayClient = new RelayClient(
                    BuildConfig.PHYLAX_RELAY_BASE_URL, BuildConfig.PHYLAX_APPROVAL_HOST, networkExecutor);
        } catch (RuntimeException error) {
            showTerminalError("This build is not configured for an approval relay");
            return;
        }
        processIntent(getIntent());
    }

    /** Process approval links delivered while this activity is already open. */
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        processIntent(intent);
    }

    /** Construct the dependency-free native approval interface. */
    private void buildInterface() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER_HORIZONTAL);
        layout.setPadding(48, 72, 48, 48);

        TextView title = new TextView(this);
        title.setText("Phylax approval");
        title.setTextSize(28f);
        layout.addView(title, matchWidthWrapHeight());

        detailView = new TextView(this);
        detailView.setText("Open a Phylax approval link to continue.");
        detailView.setTextSize(18f);
        detailView.setPadding(0, 48, 0, 32);
        layout.addView(detailView, matchWidthWrapHeight());

        statusView = new TextView(this);
        statusView.setText("Waiting for an approval link");
        statusView.setTextSize(15f);
        statusView.setPadding(0, 0, 0, 32);
        layout.addView(statusView, matchWidthWrapHeight());

        approveButton = new Button(this);
        approveButton.setText("Approve with biometrics");
        approveButton.setEnabled(false);
        approveButton.setOnClickListener(view -> beginDecision(CanonicalApprovalEncoder.APPROVED));
        layout.addView(approveButton, matchWidthWrapHeight());

        denyButton = new Button(this);
        denyButton.setText("Deny with biometrics");
        denyButton.setEnabled(false);
        denyButton.setOnClickListener(view -> beginDecision(CanonicalApprovalEncoder.DENIED));
        layout.addView(denyButton, matchWidthWrapHeight());

        setContentView(layout);
    }

    /** Return standard full-width layout parameters. */
    private static LinearLayout.LayoutParams matchWidthWrapHeight() {
        return new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
    }

    /** Validate a deep link and retrieve its immutable public approval metadata. */
    private void processIntent(Intent intent) {
        disableActions();
        approvalRequest = null;
        pickupHandle = null;
        if (intent == null || !Intent.ACTION_VIEW.equals(intent.getAction())) {
            return;
        }
        String handle = ApprovalLink.extractPickup(
                intent.getDataString(), BuildConfig.PHYLAX_APPROVAL_HOST);
        if (handle == null) {
            showTerminalError("Invalid approval link");
            return;
        }
        pickupHandle = handle;
        statusView.setText("Loading approval details");
        relayClient.fetchApproval(handle, new RelayClient.Callback() {
            /** Validate and display the relay response on the UI thread. */
            @Override
            public void onSuccess(JSONObject response) {
                runOnUiThread(() -> acceptApprovalResponse(response));
            }

            /** Display a sanitized network failure on the UI thread. */
            @Override
            public void onFailure(String message) {
                runOnUiThread(() -> showTerminalError(message));
            }
        });
    }

    /** Enforce enrollment, expiry, and device binding before enabling decisions. */
    private void acceptApprovalResponse(JSONObject response) {
        try {
            if (!signer.hasVerifiedKey()) {
                showTerminalError("This phone is not enrolled with a verified StrongBox key");
                return;
            }
            String enrolledDeviceId = getSharedPreferences(
                    ENROLLMENT_PREFERENCES, MODE_PRIVATE)
                    .getString(DEVICE_ID_PREFERENCE, "");
            ApprovalRequest parsed = ApprovalRequest.fromJson(response);
            if (enrolledDeviceId.isEmpty() || !enrolledDeviceId.equals(parsed.deviceId)) {
                showTerminalError("This approval belongs to a different enrolled phone");
                return;
            }
            if (Instant.now().getEpochSecond() >= parsed.expiresAt) {
                showTerminalError("This approval has expired");
                return;
            }
            if (!parsed.digestMatches()) {
                showTerminalError("Approval details do not match the signed request");
                return;
            }
            approvalRequest = parsed;
            detailView.setText(
                    "Agent: " + parsed.agentName
                            + "\nAction: " + parsed.action
                            + "\nCategory: " + parsed.category
                            + "\nTarget: " + parsed.targetName);
            statusView.setText("Confirm the exact request, then authorize one decision");
            approveButton.setEnabled(true);
            denyButton.setEnabled(true);
        } catch (Exception error) {
            showTerminalError("Approval details failed validation");
        }
    }

    /** Prepare an exact decision signature and request one strong biometric operation. */
    private void beginDecision(byte decision) {
        ApprovalRequest request = approvalRequest;
        if (request == null || Instant.now().getEpochSecond() >= request.expiresAt) {
            showTerminalError("This approval has expired");
            return;
        }
        disableActions();
        long issuedAt = Instant.now().getEpochSecond();
        try {
            byte[] canonicalMessage = request.canonicalMessage(decision, issuedAt);
            Signature signature = signer.prepareSignature(canonicalMessage);
            BiometricPrompt prompt = new BiometricPrompt.Builder(this)
                    .setTitle(decision == CanonicalApprovalEncoder.APPROVED
                            ? "Approve this exact request" : "Deny this exact request")
                    .setSubtitle("Phylax will accept only this one signed decision")
                    .setNegativeButton("Cancel", getMainExecutor(), (dialog, which) -> {
                        statusView.setText("Decision canceled");
                        enableActionsIfCurrent();
                    })
                    .build();
            prompt.authenticate(
                    new BiometricPrompt.CryptoObject(signature),
                    new CancellationSignal(),
                    getMainExecutor(),
                    biometricCallback(request, decision, issuedAt));
        } catch (Exception error) {
            showTerminalError("StrongBox could not prepare this decision");
        }
    }

    /** Build the one-shot biometric callback for a prepared approval signature. */
    private BiometricPrompt.AuthenticationCallback biometricCallback(
            ApprovalRequest request, byte decision, long issuedAt) {
        return new BiometricPrompt.AuthenticationCallback() {
            /** Submit the signature produced by the authenticated CryptoObject. */
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                try {
                    BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
                    if (cryptoObject == null || cryptoObject.getSignature() == null) {
                        throw new IllegalStateException("authenticated signature missing");
                    }
                    byte[] signature = cryptoObject.getSignature().sign();
                    submitSignedDecision(request.signedDecision(decision, issuedAt, signature));
                } catch (Exception error) {
                    showTerminalError("Authenticated decision could not be signed");
                }
            }

            /** Keep the approval pending after a recoverable biometric mismatch. */
            @Override
            public void onAuthenticationFailed() {
                statusView.setText("Biometric did not match");
            }

            /** Return to the pending request after a canceled or failed prompt. */
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errorMessage) {
                statusView.setText("Biometric authorization did not complete");
                enableActionsIfCurrent();
            }
        };
    }

    /** Deliver the signed envelope through the untrusted relay. */
    private void submitSignedDecision(JSONObject signedDecision) {
        statusView.setText("Delivering signed decision");
        relayClient.submitDecision(pickupHandle, signedDecision, new RelayClient.Callback() {
            /** Mark the one-shot approval completed after relay acceptance. */
            @Override
            public void onSuccess(JSONObject response) {
                runOnUiThread(() -> {
                    approvalRequest = null;
                    pickupHandle = null;
                    disableActions();
                    detailView.setText("Decision delivered");
                    statusView.setText("Phylax accepted the signed decision");
                });
            }

            /** Preserve the pending request when delivery fails. */
            @Override
            public void onFailure(String message) {
                runOnUiThread(() -> {
                    statusView.setText(message);
                    enableActionsIfCurrent();
                });
            }
        });
    }

    /** Disable both decision actions during validation or signing. */
    private void disableActions() {
        if (approveButton != null) {
            approveButton.setEnabled(false);
        }
        if (denyButton != null) {
            denyButton.setEnabled(false);
        }
    }

    /** Re-enable actions only while the same request remains unexpired. */
    private void enableActionsIfCurrent() {
        if (approvalRequest != null
                && Instant.now().getEpochSecond() < approvalRequest.expiresAt) {
            approveButton.setEnabled(true);
            denyButton.setEnabled(true);
        }
    }

    /** Display a terminal, sanitized failure and disable all actions. */
    private void showTerminalError(String message) {
        approvalRequest = null;
        pickupHandle = null;
        disableActions();
        detailView.setText("Approval unavailable");
        statusView.setText(message);
    }
}
