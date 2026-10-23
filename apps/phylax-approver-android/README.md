# phylax-approver-android

Android approver for Phylax exact-phone approvals. It opens a relay pickup
link, shows the pending operation, and signs approve or deny with a key that
never leaves the phone's StrongBox.

## What the app checks before it signs

- The link is an exact HTTPS App Link on the configured host, with the
  `/v1/phone/open/` prefix and a 43-character pickup handle.
- The relay origin is the configured host. Cleartext traffic is disabled.
- The request digest recomputes from the displayed agent, category, target,
  action, approval id, and expiry, plus one opaque hash of the fields the
  phone does not show. On mismatch the buttons stay disabled.
- Every signature needs a strong biometric. The key is invalidated when
  biometric enrollment changes, and it requires an unlocked device.
- Screens are `FLAG_SECURE` and backups are off.

## Status

Not usable yet. There is no enrollment screen, so the app has no device id
and rejects every approval as not enrolled. phylaxd has no enrollment route
either.

## Build

The approval host is a Gradle property. It drives the App Link intent filter
and the relay pin. No Gradle wrapper is checked in; use Gradle 8.13 or newer
(required by Android Gradle Plugin 8.13) with JDK 21 and an Android SDK that
has platform 36.

```sh
gradle assembleRelease lintDebug \
  -PphylaxApprovalHost=approve.your-domain.example \
  -PphylaxRelayBaseUrl=https://approve.your-domain.example
```

Without `phylaxApprovalHost` the app pins `approve.example.com`.

`lintDebug` must report 0 errors. It enforces `minSdk 31`, which is why the
encoders append bytes with `write(bytes, 0, length)` rather than
`writeBytes`, an API 33 call that would crash on Android 12.

## Tests

The protocol tests are dependency-free Java `main` classes under
`app/src/test/java`. They pin the same golden vectors as the Rust tests in
`kleos-phylax`, so a byte-level drift between the two fails both sides.

```sh
javac -d out app/src/main/java/phylax/approver/{RequestDigestEncoder,CanonicalApprovalEncoder,ApprovalLink}.java app/src/test/java/phylax/approver/*.java
java -cp out phylax.approver.RequestDigestEncoderTest
java -cp out phylax.approver.CanonicalApprovalEncoderTest
java -cp out phylax.approver.ApprovalLinkTest
```
