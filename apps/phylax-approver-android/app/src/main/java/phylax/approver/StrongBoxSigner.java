package phylax.approver;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/** Owns the non-exportable StrongBox key used for exact-phone decisions. */
public final class StrongBoxSigner {
    /** Stable Android Keystore alias for the enrolled approval key. */
    private static final String KEY_ALIAS = "phylax-exact-phone-v1";

    /** Creates a StrongBox signer facade without touching key material. */
    public StrongBoxSigner() {}

    /** Return whether the enrolled key exists and is proven StrongBox-backed. */
    public boolean hasVerifiedKey() {
        try {
            KeyStore store = KeyStore.getInstance("AndroidKeyStore");
            store.load(null);
            PrivateKey key = (PrivateKey) store.getKey(KEY_ALIAS, null);
            if (key == null) {
                return false;
            }
            KeyInfo info = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore")
                    .getKeySpec(key, KeyInfo.class);
            return info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_STRONGBOX
                    && info.isUserAuthenticationRequired();
        } catch (Exception error) {
            return false;
        }
    }

    /** Generate a non-exportable per-use biometric key for a server challenge. */
    public void generateForEnrollment(byte[] attestationChallenge) throws Exception {
        if (attestationChallenge == null || attestationChallenge.length != 32) {
            throw new IllegalArgumentException("enrollment challenge must be 32 bytes");
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(true)
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(true)
                .setAttestationChallenge(attestationChallenge)
                .build();
        generator.initialize(spec);
        try {
            generator.generateKeyPair();
        } catch (StrongBoxUnavailableException error) {
            throw new IllegalStateException("StrongBox is required and unavailable", error);
        }
        if (!hasVerifiedKey()) {
            throw new IllegalStateException("generated key did not verify as StrongBox-backed");
        }
    }

    /** Initialize SHA-256 ECDSA for one BiometricPrompt CryptoObject. */
    public Signature prepareSignature(byte[] canonicalMessage) throws Exception {
        if (!hasVerifiedKey()) {
            throw new IllegalStateException("verified StrongBox key is unavailable");
        }
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        PrivateKey key = (PrivateKey) store.getKey(KEY_ALIAS, null);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(key);
        signature.update(canonicalMessage);
        return signature;
    }

    /** Return the hardware attestation certificate chain for local enrollment. */
    public java.security.cert.Certificate[] attestationChain() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        java.security.cert.Certificate[] chain = store.getCertificateChain(KEY_ALIAS);
        if (chain == null || chain.length < 2) {
            throw new IllegalStateException("StrongBox attestation chain is unavailable");
        }
        return chain;
    }
}
