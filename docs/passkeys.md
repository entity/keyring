# Passkeys & Security Keys

- [Introduction](#introduction)
- [The Two Profiles](#the-two-profiles)
- [What a Key Proves](#what-a-key-proves)
- [Relying Party and Origins](#relying-party-and-origins)
- [Signature Algorithms](#signature-algorithms)
    - [RS256 and Windows Hello](#rs256-and-windows-hello)
- [Attestation and AAGUIDs](#attestation-and-aaguids)
    - [Requiring Attestation](#requiring-attestation)
    - [Attestation and AAL3](#attestation-and-aal3)
    - [Allowing Only Certain Models](#allowing-only-certain-models)
    - [Trusting Each Model Separately](#trusting-each-model-separately)
    - [What Is Kept](#what-is-kept)
- [Counters and Cloned Keys](#counters-and-cloned-keys)
- [Signing In Without a Username](#signing-in-without-a-username)
- [Laravel's Passkeys Client](#laravels-passkeys-client)
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

- A passkey always requires user verification, so it proves possession and inherence, and reaches [AAL2](policies.md#assurance-levels) on its own. Most passkeys sync between devices (iCloud Keychain, Google Password Manager), and NIST caps those at AAL2.
- A security key that doesn't verify the user proves possession only. After a password, that's AAL2.
- Whether a key may sync is the backup-eligible flag it reports. Keyring reads it on every sign in, not just at registration, and a key that hasn't reported it counts as synced. A key that says it can't is "device bound": `Requirement::deviceBound()` and `keyring:aal2,device-bound` ask for one.
- AAL3 takes more than that flag, which is only the key's word. The key has to have been added with a [verified attestation](#requiring-attestation), and its second factor has to be its own user verification or a password. See [Attestation and AAL3](#attestation-and-aal3).

When planning what to offer, Keyring assumes a security key will verify the user if it did so when it was registered. The categories that count are always the ones from the actual response.

## Relying Party and Origins

```php
'webauthn' => [
    'relying_party' => [
        'id' => env('KEYRING_WEBAUTHN_RP_ID'),
        'name' => env('KEYRING_WEBAUTHN_RP_NAME'),
    ],
    'origins' => [],
    'timeout' => '60s',
    'attestation_roots' => [],
],
```

- **`relying_party.id`** is the domain keys are bound to. It defaults to the host of `APP_URL`. Keys registered for `example.com` also work on its subdomains, so set it to your registrable domain if users sign in on more than one subdomain. Changing it later makes existing keys stop working.
- **`relying_party.name`** is shown by some browsers when creating a key. It defaults to `APP_NAME`.
- **`origins`** lists the exact origins (`scheme://host[:port]`) allowed to complete a ceremony. When empty, only the `APP_URL` origin is allowed. Each entry has to be a full URL: if none is (a host name on its own, or an `APP_URL` with no scheme), Keyring refuses every passkey and security key response and reports an exception saying so. If you set a relying party ID that covers several subdomains, list each origin here.
- **`timeout`** is how long the browser waits, as a [duration](configuration.md#durations).
- **`attestation_roots`** are the certificates a key's attestation has to chain to, for a factor that [requires attestation](#requiring-attestation).
- **`algorithms`** and **`minimum_rsa_bits`** decide which [signatures](#signature-algorithms) keys may use.

For local development, `APP_URL` must match the address in your browser, for example `http://localhost:8000`. Browsers only allow WebAuthn on `https` origins and on `localhost`.

## Signature Algorithms

`webauthn.algorithms` lists the signature algorithms keys may use, in order of preference:

```php
'webauthn' => [
    'algorithms' => ['ES256', 'EdDSA'],
    'minimum_rsa_bits' => 2048,
],
```

| Name | Algorithm | |
|---|---|---|
| `ES256` | ECDSA with P-256 and SHA-256 | Nearly every authenticator supports it. |
| `EdDSA` | Ed25519 | Only offered when PHP's `sodium` extension is loaded. |
| `RS256` | RSASSA-PKCS1-v1_5 with SHA-256 | Off by default. See below. |

Only these are offered to the browser, and only these are accepted: a new key that signs with anything else is refused, and so is a sign in with a stored key whose algorithm has since been taken off the list. Its owner then needs another way in, so check what your users have before removing one. An empty list, or a name that isn't one of the three, throws rather than falling back to anything.

The list covers the signature on an [attestation statement](#requiring-attestation) too.

### RS256 and Windows Hello

RS256 is left out because OWASP ASVS 5.0 doesn't approve it: its padding (PKCS #1 v1.5) is on the disallowed list of Appendix C, and the 2048 bit keys that use it give 112 bits of strength where ASVS 11.2.3 asks for 128. ES256 and Ed25519 are approved and give 128. NIST SP 800-63B asks for 112, so RS256 with a 2048 bit key meets NIST but not ASVS.

The cost of leaving it out falls on Windows. Windows Hello signed with RS256 alone for years, and still does on some machines: older builds, and ones where it has no TPM that makes ES256 keys. There the browser can't create a passkey with Windows Hello while RS256 isn't offered, and the user is shown a phone or a security key to use, or an error. They can still add a passkey from a phone or a hardware key, or sign in with their password and another second factor.

If those users matter more to you than ASVS conformance here, add it, last so every other authenticator keeps choosing a stronger one:

```php
'algorithms' => ['ES256', 'EdDSA', 'RS256'],
```

Record that as a deviation from ASVS 11.6.1 and 11.2.3 if you assess against it.

With RS256 on, Keyring refuses an RSA key shorter than `minimum_rsa_bits`, both when it's added and at every sign in, and never takes one under 2048 bits however low that's set (RFC 8230 requires 2048 for RS256). Raising it to 3072 would give RSA the 128 bits ASVS asks for, but Windows Hello's RSA keys are 2048 bits, so in practice it refuses the keys RS256 was turned on for, after the browser has already made them. If you want 128 bits throughout, leave RS256 off.

## Attestation and AAGUIDs

By default Keyring registers keys without attestation. It asks the browser for `none` attestation and only accepts `none` attestation statements. That means any authenticator is accepted, including passkeys synced through a password manager or a platform account.

Each key's AAGUID (its model identifier) is stored in the `aaguid` column. Without attestation, the AAGUID is only what the key says about itself, and nothing checks it. It's fine for showing a friendly model name. It isn't a way to allow only certain models: a key, or software pretending to be one, can report any AAGUID.

### Requiring Attestation

An app that only accepts certain hardware keys can ask each new key to prove who made it. The key sends a statement signed with a certificate its maker put on it, and Keyring only adds the key when that certificate chains to a root you trust:

```php
Keyring::factors([
    Password::class,
    WebAuthn::passkeys(),
    WebAuthn::securityKeys()->requireAttestation(),
]);
```

List the makers' root certificates in `config/keyring.php`, as PEM text or as paths to PEM files. A file can hold several. Makers publish theirs, and Keyring never downloads anything:

```php
'webauthn' => [
    'attestation_roots' => [
        storage_path('attestation/yubico-fido-root-ca.pem'),
    ],
],
```

With that set, for this factor:

- Keyring asks the browser for `direct` attestation. Some browsers ask the user before they pass it on, and a user who says no sends `none`.
- A key is added only when its statement is valid and its certificates chain to one of the roots, each within its dates, each signed by a certificate that is allowed to sign others (a root itself is trusted as listed, whatever it says about signing), with no SHA-1 signature or RSA key under 2048 bits on the way.
- `none`, a key that attests for itself, a chain to any other root and a statement that doesn't match the response are all refused the same way, and nothing is added. The error is `keyring::keyring.key_not_accepted`, which tells the person this isn't a key the site takes, since trying again wouldn't help.
- If no root is listed, or one can't be read, every key is refused and Keyring reports an exception saying which.

Two formats are read: `packed`, which FIDO2 keys use, and `fido-u2f`, which older keys use. Those are what hardware security keys send. The formats platforms use (`tpm`, `android-key`, `apple`) and `compound` are refused, as is any other.

Each setting belongs to one factor, so passkeys carry on as before. That matters: passkeys that sync between devices send no attestation worth checking, and requiring it on `WebAuthn::passkeys()` would turn nearly all of them away. Keep it for security keys, or for a second key of its own:

```php
WebAuthn::securityKeys()->as('staff-key')->requireAttestation(),
```

Certificates aren't looked up for revocation, since that needs the network. If a maker withdraws a root, take it out of the list. Keys added before then stay: attestation is checked once, when a key is added.

### Attestation and AAL3

A key reaches [AAL3](policies.md#assurance-levels) only when its factor uses `requireAttestation()` and the key was added with an attestation Keyring verified, which is what the `attestation` column records. Nothing else tells a hardware key from software that reports the same flags.

- Keys added before the factor asked for attestation have nothing in that column and stay at AAL2. Their owners add them again to reach AAL3.
- Take `requireAttestation()` off a factor and its keys stop reaching AAL3, whatever the column says.
- The attestation is for the key. Its second factor still has to be its own user verification or a password: touching an attested key after signing in with a synced passkey is AAL2.

NIST AAL3 also needs the authenticator validated to FIPS 140 (Sec. 2.3.2). Attestation says which model a key is, not whether that model was validated, so use `allowOnly()` to accept only the models you've checked.

### Allowing Only Certain Models

Give the AAGUIDs of the models you accept. Their makers publish them:

```php
WebAuthn::securityKeys()
    ->requireAttestation()
    ->allowOnly([
        '2fc0579f-8113-47ea-b116-bb5a8db9202a',
        'ee882879-721c-4913-9775-3dfcce97072a',
    ]),
```

The list only works with `requireAttestation()`. Without it, Keyring throws a `LogicException` when a user starts adding a key, since the list would accept anything that claims an AAGUID on it.

Keys that only speak U2F have no AAGUID (they report all zeros), so a list leaves them out.

Every root in `attestation_roots` is trusted for every model. If you trust more than one maker, any of them could issue a certificate for another's AAGUID. When that matters, [trust each model separately](#trusting-each-model-separately).

### Trusting Each Model Separately

Keyring asks `Keyring\Contracts\TrustsAuthenticators` for the roots a model's attestation may chain to. The default reads `attestation_roots` and answers the same for every model. Bind your own to answer per AAGUID. That's also how to use the FIDO Metadata Service: download its blob, verify it and keep it up to date yourself, and answer with each model's roots from it, leaving out the models it reports as compromised.

```php
use Keyring\Contracts\TrustsAuthenticators;

class ModelRoots implements TrustsAuthenticators
{
    public function roots(string $aaguid): array
    {
        return match ($aaguid) {
            '2fc0579f-8113-47ea-b116-bb5a8db9202a' => [file_get_contents(storage_path('attestation/yubico-fido-root-ca.pem'))],
            default => [],
        };
    }
}

$this->app->bind(TrustsAuthenticators::class, ModelRoots::class);
```

Return PEM certificates, or the bare base64 a metadata statement lists in `attestationRootCertificates`. A model with no roots is refused. U2F keys ask with an AAGUID of all zeros.

### What Is Kept

When a key passes, its `attestation` column holds the kind of attestation that was checked (`basic`, a certificate its maker shares across a batch of keys), and the certificates it sent are kept with the credential record in `public_key`. The column is `null` for every key added without the check, and then `aaguid` is still only what the key reported.

## Counters and Cloned Keys

Each assertion carries a signature counter, which Keyring stores in `sign_count`. If a key presents a counter lower than the last one seen, that suggests a cloned key. Keyring refuses that sign in and dispatches `Keyring\Events\CloneSuspected`, which is logged and can send the `clone_suspected` [security email](security-log-and-emails.md#security-emails).

Synced passkeys usually report a counter of zero every time, so this check doesn't apply to them.

## Signing In Without a Username

Passkeys sign in on their own:

1. The browser fetches `GET /login/passkey/options`, which answers `{ "options": { ... } }`. The options have an empty `allowCredentials` and require user verification. Keyring keeps the challenge in the session.
2. The user picks a passkey, and the browser posts the response to `POST /login/passkey` as `credential`.
3. Keyring finds the passkey by its credential ID, among those of the model behind its guard, checks the signature, and continues with the [policy](policies.md) as for any login.

The same options work for autofill, where the browser lists passkeys in the email field (give the field `autocomplete="username webauthn"`). The browser package's `usePasskeyLogin({ autofill: true })` starts that for you. See [Frontend](frontend.md#signing-in-with-a-passkey). The client in Laravel's starter kits can sign in through these two routes as well. See [Laravel's Passkeys Client](#laravels-passkeys-client).

A challenge works once, for this kind of sign in only: trying it spends it, even if the sign in fails, and it can't finish the second factor of a password login or a step-up. Those use the challenge their own page issued.

These requests don't name an account, so only the per-IP [rate limit](security.md#rate-limiting) applies. Junk requests can't fill a bucket every user shares. Fetching the options has its own limit of 60 requests a minute per IP address, so a login page that reloads (and an office sharing one address) doesn't run out.

Security keys can't do this. `/login/security-key` and `/login/security-key/options` return a `404`.

## Laravel's Passkeys Client

Keyring's passkey routes are driven by [`@entity/keyring`](frontend.md). `@laravel/passkeys`, the client in Laravel's starter kits, is written for the routes of the `laravel/passkeys` Composer package. Each call lets you change its two paths, but not the method it uses or the JSON it reads. That's enough for signing in, which works against Keyring's two login routes. Adding a passkey and step-up don't fit. Checked against `@laravel/passkeys` 0.2.0 and 0.4.1, and `laravel/passkeys` 0.3.0:

| What the client does | What Keyring does |
|---|---|
| Signing in, it reads `options` from the JSON of `GET /passkeys/login/options`. | The same. `GET /login/passkey/options` answers `{ "options": { ... } }`. |
| It posts `{ credential, remember }` to `/passkeys/login` and reads `redirect`. | The same. `POST /login/passkey` answers `{ "status": "authenticated", "redirect": "..." }`. |
| Adding a passkey, it reads `options` from `GET /user/passkeys/options`. | Enrolling begins with a `POST` to `/user/authenticators/passkey`, and the options are under `enrollment.options`. |
| It posts `{ name, credential }` to `/user/passkeys`. `usePasskeyRegister()` doesn't pass the response on. | `POST /user/authenticators/passkey/confirm` takes those fields, but its response can carry [recovery codes](authenticators.md#recovery-codes) that are only shown once. |
| Confirming, it reads `options` from `GET /passkeys/confirm/options`. | [Step-up](step-up.md) has no options route. The confirm page gets the options as props, for whichever of the user's authenticators comes next. |

### Signing In With It

Give the client Keyring's two login routes:

```ts
import { Passkeys } from '@laravel/passkeys'

const { redirect } = await Passkeys.verify({
  routes: { options: '/login/passkey/options', submit: '/login/passkey' },
  remember: true,
})

if (redirect) {
  window.location.href = redirect
}
```

The React and Vue hooks take the same `routes`, for the button and for autofill:

```tsx
import { usePasskeyVerify } from '@laravel/passkeys/react'

const { verify, isLoading, error, isSupported } = usePasskeyVerify({
  autofill: true,
  remember: () => form.data.remember,
  routes: { options: '/login/passkey/options', submit: '/login/passkey' },
  onSuccess: ({ redirect }) => {
    if (redirect) {
      window.location.href = redirect
    }
  },
})
```

```vue
<script setup lang="ts">
import { usePasskeyVerify } from '@laravel/passkeys/vue'

const { verify, isLoading, error, isSupported } = usePasskeyVerify({
  autofill: true,
  remember: () => form.remember,
  routes: { options: '/login/passkey/options', submit: '/login/passkey' },
  onSuccess: ({ redirect }) => {
    if (redirect) {
      window.location.href = redirect
    }
  },
})
</script>
```

A few things to know:

- Always go to `redirect`. It's the page the user was after, or the [challenge page](sign-in-flow.md#the-challenge-page) when your [policy](policies.md) asks for another factor after the passkey.
- A passkey that's refused answers `422`, and a rate limit `429`. The client throws either with the message in the answer, which the hooks return as `error`. That goes for autofill too, so a login page reloaded past the options limit shows that message, where Keyring's helper stays quiet.
- For autofill, the email field needs `autocomplete="username webauthn"`. The client expects a field whose `autocomplete` ends in `webauthn`.
- `remember` came in `@laravel/passkeys` 0.4. Older versions leave it out, and the user isn't remembered.
- If you [changed the route prefix](configuration.md#routes), put it in front of both paths.

Every check is the same as for Keyring's own helper: the per-IP limits, the single-use challenge and the policy.

### Adding a Passkey and Step-Up

These still need `@entity/keyring`. Fitting the client would take a second set of routes for the same ceremonies, so Keyring doesn't try. Use [`enroll()`](frontend.md#managing-authenticators) to add a passkey and [`useChallenge()`](frontend.md#the-challenge-page) for the challenge and confirm pages. [`usePasskeyLogin()`](frontend.md#signing-in-with-a-passkey) signs in through the same two routes, as an Inertia visit, if you'd rather use one package for everything. Passkeys made with `laravel/passkeys` keep working once [imported](upgrading-from-fortify.md#importing-two-factor-data).

## Customising a Profile

Register the same profile under a second key, for example to treat hardware keys from one program separately:

```php
WebAuthn::securityKeys()->as('backup-key'),
```

Require user verification for security keys:

```php
WebAuthn::securityKeys()->requireUserVerification(),
```

Only accept keys whose maker vouches for them, or only certain models (see [Attestation and AAGUIDs](#attestation-and-aaguids)):

```php
WebAuthn::securityKeys()->requireAttestation()->allowOnly([$aaguid]),
```

Each returns a new instance. A factor key other than `passkey` or `security-key` needs a line in the frontend's [factor map](frontend.md#the-challenge-page). The browser package's `confirmEnrollment()` decides whether to run the WebAuthn ceremony from the options the server sends, so it works for any key:

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
| `attestation` | The kind of attestation that was checked against your roots when the key was added (`basic`), which is what vouches for `aaguid`. `null` when none was. |
| `transports` | How the browser can reach the key (`usb`, `nfc`, `internal`...). |
| `meta.user_verified` | Whether the key verified the user when registered. |
| `meta.backup_eligible` | Whether the key said it can be synced. |
| `meta.backed_up` | Whether the key said it has been backed up, which a key that can sync may not have been yet. Read again on every sign in, like `backup_eligible`. Keyring only records it: assurance goes by whether the key can sync at all. |

The user handle given to authenticators is an HMAC of the user's ID, under a key derived from `APP_KEY` for that purpose alone, never their real ID or email. Once a user has a key, new ones reuse its handle, so rotating `APP_KEY` doesn't make password managers list the account twice.

To test passkeys without a browser, see [VirtualAuthenticator](testing.md#virtual-authenticators).
