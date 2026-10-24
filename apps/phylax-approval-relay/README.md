# phylax-approval-relay

Relay for Phylax exact-phone approvals. phylaxd tells the relay that an
approval is waiting. The relay sends a Telegram message containing a pickup
link. The phone opens the link and fetches the approval details, and the relay
forwards the phone's signed decision back to phylaxd.

The relay is untrusted by design. It holds the one-use decision capability
but never returns it to a client. It cannot forge a decision on a
phone-required approval, because phylaxd then accepts only a decision signed
by the enrolled phone key. The phone
recomputes the request digest from the fields it displays and refuses to sign
on a mismatch, so a compromised relay cannot get a different operation
approved than the one shown.

This crate is not a workspace member. Build and test it from this directory.

## Status

Exact-phone approvals cannot be activated yet. Phone enrollment has no route
or CLI on the phylaxd side and no screen in the Android app. Leave
`PHYLAX_PHONE_APPROVAL_REQUIRED` unset until enrollment ships.

## Build

The public origin is pinned at build time. A build without the variable pins
`https://approve.example.com` and will refuse any other runtime origin.

```sh
PHYLAX_APPROVAL_ORIGIN=https://approve.your-domain.example cargo build --release
```

## Configuration

Every value comes from the process environment. Startup fails closed on any
invalid value.

| Variable | Required | Rule |
|----------|----------|------|
| `PHONE_PUBLIC_BASE_URL` | yes | HTTPS origin with no path, query, or userinfo. Must equal the build-time `PHYLAX_APPROVAL_ORIGIN`. |
| `PHYLAXD_URL` | yes | `http://` origin with an explicit port and a literal loopback or private IPv4 address. |
| `PHYLAX_NOTIFY_TOKEN` | yes | 256-bit unpadded base64url bearer, 43 characters. phylaxd sends the same value. |
| `NOTIFY_BIND` | yes | Notification intake listener. Must be a private IPv4 address, for example a VPN interface. |
| `PHONE_BIND` | no, default `127.0.0.1:8788` | Public API listener. Must be loopback; put TLS ingress or a tunnel in front of it. |
| `TELEGRAM_BOT_TOKEN` | yes | Bot used to send pickup links. Telegram only carries the link. |
| `TELEGRAM_CHAT_ID` | yes | The one chat that receives links. |

On the phylaxd side, set `PHYLAX_NOTIFY_URL` to `http://<NOTIFY_BIND>/notify`
and `PHYLAX_NOTIFY_TOKEN` to the same token. phylaxd only notifies a literal
private IPv4 address with an explicit port. A notifier that is down never
blocks or fails an approval.

## Routes

| Listener | Method | Path | Purpose |
|----------|--------|------|---------|
| intake | `POST` | `/notify` | Bearer-authenticated notification from phylaxd. |
| public | `GET` | `/v1/phone/open/{pickup}` | Landing page for the App Link. |
| public | `GET` | `/v1/phone/requests/{pickup}` | Approval details for the phone. |
| public | `POST` | `/v1/phone/requests/{pickup}/decision` | Signed decision from the phone, forwarded to phylaxd. |

Pickup handles are random 43-character base64url values. State is bounded and
expires with the approval. A decision that phylaxd rejects with 4xx consumes
the pickup handle; a 5xx keeps it so the phone can retry.

The Android App Link needs `/.well-known/assetlinks.json` on the public host.
The relay does not serve it, so publish it from your ingress.
