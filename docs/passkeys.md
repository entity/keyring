# Passkeys & Security Keys

- [Introduction](#introduction)
- [The Two Profiles](#the-two-profiles)
- [What a Key Proves](#what-a-key-proves)
- [Relying Party and Origins](#relying-party-and-origins)
- [Signature Algorithms](#signature-algorithms)
- [Attestation and AAGUIDs](#attestation-and-aaguids)
- [Counters and Cloned Keys](#counters-and-cloned-keys)
- [Signing In Without a Username](#signing-in-without-a-username)
- [Customising a Profile](#customising-a-profile)
- [Stored Data](#stored-data)

## Introduction

Keyring supports WebAuthn through one factor class, `Keyring\Factors\WebAuthn`, with two profiles. Register either or both:

```php
use Keyring\Factors\WebAuthn;

Keyring::factors([
    Password::class,
    WebAuthn::passkeys(),
    WebAuthn::securityKeys(),
    // ...
]);
```

WebAuthn verifications are phishing resistant: the browser binds every response to your site's origin, so a look-alike site can't use it. Keyring uses `web-auth/webauthn-lib` for the ceremonies.

## The Two Profiles

| | `WebAuthn::passkeys()` | `WebAuthn::securityKeys()` |
|---|---|---|
| Key | `passkey` | `security-key` |
| Discoverable (resident key) | required | discouraged |
| User verification | required | preferred |
| Authenticator attachment | any (platform or roaming) | cross-platform only |
| Can start a login | yes, without a username | no, only as a further factor |
| Priority | 100 | 90 |

Users add either through the [authenticator routes](authenticators.md). Keyring excludes every WebAuthn credential the user already has when it asks the browser for a new one, and refuses a credential that's already registered to any account.

## What a Key Proves

Every WebAuthn verification proves possession. It also proves inherence only when the authenticator reports that it verified the user this time (the UV flag), with a PIN, fingerprint or face.

- A passkey always requires user verification, so it proves possession and inherence, and reaches [AAL2](policies.md#assurance-levels) on its own. Most passkeys sync between devices (iCloud Keychain, Google Password Manager), and NIST caps those at AAL2. A passkey that stays on its device reaches AAL3.
- A security key that doesn't verify the user proves possession only. After a password, that's AAL3, since the key is phishing resistant and can't leave its device.
- Whether a key may sync is the backup-eligible flag it reports. Keyring reads it on every sign in, not just at registration, and a key that hasn't reported it counts as synced.

When planning what to offer, Keyring assumes a security key will verify the user if it did so when it was registered. The categories that count are always the ones from the actual response.

## Relying Party and Origins

```php
'webauthn' => [
    'relying_party' => [
        'id' => env('KEYRING_WEBAUTHN_RP_ID'),
        'name' => env('KEYRING_WEBAUTHN_RP_NAME'),
    ],
    'origins' => [],
    'timeout' => 60_000,
],
```

- **`relying_party.id`** is the domain keys are bound to. It defaults to the host of `APP_URL`. Keys registered for `example.com` also work on its subdomains, so set it to your registrable domain if users sign in on more than one subdomain. Changing it later makes existing keys stop working.
- **`relying_party.name`** is shown by some browsers when creating a key. It defaults to `APP_NAME`.
- **`origins`** lists the exact origins (`scheme://host[:port]`) allowed to complete a ceremony. When empty, only the `APP_URL` origin is allowed. If you set a relying party ID that covers several subdomains, list each origin here.
- **`timeout`** is how long the browser waits, in milliseconds.

For local development, `APP_URL` must match the address in your browser, for example `http://localhost:8000`. Browsers only allow WebAuthn on `https` origins and on `localhost`.

## Signature Algorithms

Keyring offers the browser these algorithms, in order of preference, and accepts only these:

- ES256 (ECDSA with P-256), which nearly every authenticator supports,
- Ed25519 (EdDSA), only when PHP's `sodium` extension is loaded,
- RS256, for older platform authenticators.

## Attestation and AAGUIDs

Keyring registers keys without attestation. It asks the browser for `none` attestation and only accepts `none` attestation statements. That means any authenticator is accepted, including passkeys synced through a password manager or a platform account.

Each key's AAGUID (its model identifier) is stored in the `aaguid` column. Without attestation, the AAGUID is only what the key says about itself, and nothing checks it. It's fine for showing a friendly model name. It isn't a way to allow only certain models: a key, or software pretending to be one, can report any AAGUID. Restricting models would need attestation checked against the FIDO Metadata Service, which Keyring doesn't do.

## Counters and Cloned Keys

Each assertion carries a signature counter, which Keyring stores in `sign_count`. If a key presents a counter lower than the last one seen, that suggests a cloned key. Keyring refuses that sign in and dispatches `Keyring\Events\CloneSuspected`, which is logged and can send the `clone_suspected` [security email](security-log-and-emails.md#security-emails).

Synced passkeys usually report a counter of zero every time, so this check doesn't apply to them.

## Signing In Without a Username

Passkeys sign in on their own:

1. The browser fetches `GET /login/passkey/options`. The options have an empty `allowCredentials` and require user verification. Keyring keeps the challenge in the session.
2. The user picks a passkey, and the browser posts the response to `POST /login/passkey`.
3. Keyring finds the passkey by its credential ID, checks the signature, and continues with the [policy](policies.md) as for any login.

The same options work for autofill, where the browser lists passkeys in the email field (give the field `autocomplete="username webauthn"`). The browser package's `usePasskeyLogin({ autofill: true })` starts that for you. See [Frontend](frontend.md#signing-in-with-a-passkey).

These requests don't name an account, so only the per-IP [rate limit](security.md#rate-limiting) applies. Junk requests can't fill a bucket every user shares.

Security keys can't do this. `/login/security-key` and `/login/security-key/options` return a `404`.

## Customising a Profile

Register the same profile under a second key, for example to treat hardware keys from one program separately:

```php
WebAuthn::securityKeys()->as('backup-key'),
```

Require user verification for security keys:

```php
WebAuthn::securityKeys()->requireUserVerification(),
```

Both return new instances. A factor key other than `passkey` or `security-key` needs a line in the frontend's [factor map](frontend.md#the-challenge-page). The browser package's `confirmEnrollment()` decides whether to run the WebAuthn ceremony from the options the server sends, so it works for any key:

```ts
import { enroll } from '@entity/keyring'

await enroll('backup-key', { name: 'Spare key' })
```

To change more than the profile, extend the class. `passkeys()` and `securityKeys()` return `static` and the constructor is `final`, so they build your subclass:

```php
use Keyring\Factors\WebAuthn;

class AuditedWebAuthn extends WebAuthn
{
    // ...
}

Keyring::factors([AuditedWebAuthn::passkeys(), AuditedWebAuthn::securityKeys()]);
```

## Stored Data

Each key is a row in `keyring_authenticators` with:

| Column | Holds |
|---|---|
| `credential_id` | The credential ID, base64url without padding, up to 512 characters. Unique across all users. A key that sends a longer ID is refused at registration. |
| `public_key` | The full credential record as JSON, including the public key and counter. |
| `sign_count` | The last counter seen. |
| `aaguid` | The model identifier the key reported. |
| `transports` | How the browser can reach the key (`usb`, `nfc`, `internal`...). |
| `meta.user_verified` | Whether the key verified the user when registered. |
| `meta.backup_eligible` | Whether the key said it can be synced. |

The user handle given to authenticators is an HMAC of the user's ID keyed with `APP_KEY`, never their real ID or email.

To test passkeys without a browser, see [VirtualAuthenticator](testing.md#virtual-authenticators).
