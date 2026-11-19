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

Keyring supports WebAuthn through a single factor class, `Keyring\Factors\WebAuthn`, which comes in two profiles. You may register either one or both:

```php
use Keyring\Factors\WebAuthn;

Keyring::factors([
    Password::class,
    WebAuthn::passkeys(),
    WebAuthn::securityKeys(),
    // ...
]);
```

WebAuthn verifications resist phishing. The browser binds every response to your site's origin, so a look-alike site can't use it. Keyring relies on the `web-auth/webauthn-lib` package for the ceremonies.

## The Two Profiles

| | `WebAuthn::passkeys()` | `WebAuthn::securityKeys()` |
|---|---|---|
| Key | `passkey` | `security-key` |
| Discoverable (resident key) | required | discouraged |
| User verification | required | preferred |
| Authenticator attachment | any (platform or roaming) | cross-platform only |
| Can start a sign in | yes, without a username | no, only as a further factor |
| Priority | 100 | 90 |

Users may add either one through the [authenticator routes](authenticators.md). When Keyring asks the browser for a new credential, it excludes every WebAuthn credential the user already has. It also refuses any credential that's already registered to any account.

## What a Key Proves

Every WebAuthn verification proves possession. It proves inherence too, but only when the authenticator reports that it verified the user this time (the UV flag), using a PIN, fingerprint, or face.

- A passkey always requires user verification, so it proves both possession and inherence. That's enough on its own to reach [AAL2](policies.md#assurance-levels). Most passkeys sync between devices through iCloud Keychain or Google Password Manager, and NIST caps synced passkeys at AAL2.
- A security key that doesn't verify the user proves possession only. Paired with a password, that's AAL2.
- Whether a key may sync depends on the backup-eligible flag it reports. Keyring reads that flag on every sign in, and not only at registration, and a key that hasn't reported it counts as synced. A key that says it can't sync is "device bound", and `Requirement::deviceBound` and `keyring:aal2,device-bound` ask for one.
- AAL3 takes more than that flag, since the flag is only the key's word. The key has to have been added with a [verified attestation](#requiring-attestation), and its second factor has to be its own user verification or a password. See [Attestation and AAL3](#attestation-and-aal3).

When planning what to offer, Keyring assumes a security key will verify the user if it did so when it was registered. The categories that count, though, are always the ones in the actual response.

## Relying Party and Origins

The WebAuthn options live under `webauthn` in your `config/keyring.php` configuration file. These are the defaults, apart from the two [signature algorithm](#signature-algorithms) options, which are covered below:

```php
'webauthn' => [
    'relying_party' => [
        'id' => env('KEYRING_WEBAUTHN_RP_ID'),
    ],
    'origins' => [],
    'timeout' => '60s',
    'login_options_for' => '5m',
    'attestation_roots' => [],
],
```

- **`relying_party.id`** is the domain your keys are bound to. It defaults to the host of `APP_URL`. Keys registered for `example.com` also work on its subdomains, so set it to your registrable domain if users sign in on more than one subdomain. Changing it later makes existing keys stop working.
- You don't need to set a relying party name. WebAuthn deprecates it, and most browsers don't show it, so Keyring sends the relying party ID in its place.
- **`origins`** lists the exact origins (`scheme://host[:port]`) allowed to complete a ceremony. When it's empty, only the `APP_URL` origin is allowed. Each entry has to be a full URL. If none is (a host name on its own, or an `APP_URL` with no scheme), Keyring refuses every passkey and security key response and reports an exception saying so. If your relying party ID covers several subdomains, list each origin here.
- **`timeout`** controls how long the browser waits, written as a [duration](configuration.md#durations).
- **`login_options_for`** sets how long the server accepts an answer to the challenge of a [usernameless sign in](#signing-in-without-a-username). It's also a duration.
- **`attestation_roots`** hold the certificates a key's attestation has to chain to, for a factor that [requires attestation](#requiring-attestation).
- **`algorithms`** and **`minimum_rsa_bits`** decide which [signature algorithms](#signature-algorithms) keys may use.

During local development, `APP_URL` must match the address in your browser, such as `http://localhost:8000`. Browsers only allow WebAuthn on `https` origins and on `localhost`.

## Signature Algorithms

The `webauthn.algorithms` option lists the signature algorithms keys may use, in order of preference:

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

Keyring only offers these algorithms to the browser, and it only accepts these. A new key that signs with anything else is refused. So is a sign in with a stored key whose algorithm has since been taken off the list. That leaves its owner needing another way in, so check what your users have before you remove an algorithm. An empty list, or a name that isn't one of the three, throws rather than falling back to anything.

The list also covers the signature on an [attestation statement](#requiring-attestation).

### RS256 and Windows Hello

RS256 is left out because OWASP ASVS 5.0.0 doesn't approve it. Its padding, PKCS #1 v1.5, is on the disallowed list in Appendix C, and 2048 bit keys that use it give 112 bits of strength, where ASVS 11.2.3 asks for 128. ES256 and Ed25519 are approved and give 128 bits. NIST SP 800-63B-4 asks for 112 bits (Sec. 3.1.6.2), so RS256 with a 2048 bit key meets NIST but not ASVS.

Leaving it out has a cost, and that cost falls on Windows. For years, Windows Hello signed with RS256 alone, and it still does on some machines: older builds, and machines without the TPM that makes ES256 keys. On those, the browser can't create a passkey with Windows Hello while RS256 isn't offered. The user is then shown a phone or a security key to use instead, or an error. They can still add a passkey from a phone or a hardware key, or sign in with their password and another second factor.

If those users matter more to you than ASVS conformance, you may add RS256. Put it last, so every other authenticator keeps choosing a stronger algorithm:

```php
'algorithms' => ['ES256', 'EdDSA', 'RS256'],
```

If you assess against ASVS, record this as a deviation from ASVS 11.6.1 and 11.2.3.

When RS256 is enabled, Keyring refuses an RSA key shorter than `minimum_rsa_bits`. It checks when a key is added, and again at every sign in. It never accepts a key under 2048 bits, however low you set the option, because RFC 8812, Section 2, requires 2048 bits for RS256.

> [!WARNING]
> Raising `minimum_rsa_bits` to 3072 would give RSA the 128 bits ASVS asks for. But Windows Hello's RSA keys are 2048 bits. In practice, that refuses the keys RS256 was turned on for, after the browser has already made them. If you want 128 bits throughout, leave RS256 off.

## Attestation and AAGUIDs

By default, Keyring registers keys without attestation. It asks the browser for `none` attestation, and it only accepts `none` attestation statements. That means any authenticator is accepted, including passkeys synced through a password manager or a platform account.

Each key's AAGUID, its model identifier, is stored in the `aaguid` column. Without attestation, the AAGUID is only what the key says about itself, and nothing checks it. That's fine for showing a friendly model name. It isn't a way to allow only certain models, because a key, or software pretending to be one, can report any AAGUID.

### Requiring Attestation

If your application should only accept certain hardware keys, you may ask each new key to prove who made it. The key sends a statement signed with a certificate its maker put on it, and Keyring only adds the key when that certificate chains to a root you trust:

```php
Keyring::factors([
    Password::class,
    WebAuthn::passkeys(),
    WebAuthn::securityKeys()->requireAttestation(),
]);
```

List the makers' root certificates in your `config/keyring.php` configuration file, as PEM text or as paths to PEM files. A single file can hold several certificates. Makers publish their roots, and Keyring never downloads anything:

```php
'webauthn' => [
    'attestation_roots' => [
        storage_path('attestation/yubico-fido-root-ca.pem'),
    ],
],
```

With that in place, the following applies to this factor:

- Keyring asks the browser for `direct` attestation. Some browsers ask the user before passing it on, and a user who says no sends `none`.
- A key is added only when its statement is valid and its certificates chain to one of the roots. Every certificate in the chain must be within its dates, and each must be signed by a certificate that's allowed to sign others. A root itself is trusted as listed, whatever it says about signing. The chain can't include a SHA-1 signature or an RSA key under 2048 bits.
- Keyring refuses `none`, a key that attests for itself, a chain to any other root, and a statement that doesn't match the response, all in the same way. Nothing is added. The error is `keyring::keyring.key_not_accepted`, which tells the person that this isn't a key the site accepts. Trying again wouldn't help.
- If no root is listed, or if one can't be read, Keyring refuses every key and reports an exception that says which.

Keyring reads two formats: `packed`, which FIDO2 keys use, and `fido-u2f`, which older keys use. These are what hardware security keys send. It refuses the formats platforms use (`tpm`, `android-key`, and `apple`), along with `compound` and any other format.

Each setting belongs to one factor, so your passkeys carry on as before. That matters, because passkeys that sync between devices send no attestation worth checking. Requiring it on `WebAuthn::passkeys()` would turn away nearly all of them. Keep it for security keys, or for a second security key factor registered under a factor key of its own:

```php
WebAuthn::securityKeys()->as('staff-key')->requireAttestation(),
```

Keyring doesn't check certificates for revocation, since that needs the network. If a maker withdraws a root, remove it from the list. Keys added before then stay, because attestation is checked once, when a key is added.

### Attestation and AAL3

A key reaches [AAL3](policies.md#assurance-levels) only when its factor uses `requireAttestation()` and the key was added with an attestation that Keyring verified. The `attestation` column records that. Nothing else tells a hardware key apart from software that reports the same flags.

- Keys added before the factor asked for attestation have nothing in that column, so they stay at AAL2. Their owners need to add them again to reach AAL3.
- If you remove `requireAttestation()` from a factor, its keys stop reaching AAL3, whatever the column says.
- Narrowing [`allowOnly`](#allowing-only-certain-models), or taking a root out of the list, only stops more of those keys from being added. Keys already on accounts keep their level, so changing what you hand out won't lock out everyone holding the old model. When a model has to stop counting, for example because it was found to be weak, clear the column for its keys. That leaves them as second factors at AAL2. Alternatively, delete the rows to remove them:

    ```php
    Keyring::authenticatorModel()::query()->where('aaguid', $aaguid)->update(['attestation' => null]);
    ```

- The attestation applies to the key itself. Its second factor still has to be its own user verification or a password. Touching an attested key after signing in with a synced passkey only reaches AAL2.

NIST's AAL3 also requires the authenticator to be validated to FIPS 140 (Sec. 2.3.2). Attestation tells you which model a key is, but not whether that model was validated. To accept only the models you've checked, use `allowOnly`.

### Allowing Only Certain Models

List the AAGUIDs of the models you accept. Their makers publish them:

```php
WebAuthn::securityKeys()
    ->requireAttestation()
    ->allowOnly([
        '2fc0579f-8113-47ea-b116-bb5a8db9202a',
        'ee882879-721c-4913-9775-3dfcce97072a',
    ]),
```

The list only works together with `requireAttestation()`. Without it, Keyring throws a `LogicException` when a user starts adding a key, because the list would accept anything that claims an AAGUID on it.

Keys that only speak U2F have no AAGUID (they report all zeros), so the list leaves them out.

Every root in `attestation_roots` is trusted for every model. If you trust more than one maker, any of them could issue a certificate for another maker's AAGUID. When that matters to you, [trust each model separately](#trusting-each-model-separately).

### Trusting Each Model Separately

Keyring asks the `Keyring\Contracts\TrustsAuthenticators` contract for the roots a model's attestation may chain to. The default implementation reads `attestation_roots` and gives the same answer for every model. To answer per AAGUID, bind your own implementation. This is also how you use the FIDO Metadata Service. Download its blob, verify it, and keep it up to date yourself. Then answer with each model's roots from it, leaving out the models it reports as compromised.

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

Return PEM certificates, or the bare base64 certificates that a metadata statement lists in `attestationRootCertificates`. A model with no roots is refused. U2F keys ask with an AAGUID of all zeros.

### What Is Kept

When a key passes, its `attestation` column holds the kind of attestation that was checked, such as `basic`, which means a certificate the maker shares across a batch of keys. The certificates the key sent are kept with the credential record in `public_key`. The column is `null` for every key added without the check. For those keys, `aaguid` is still only what the key reported.

## Counters and Cloned Keys

Each assertion carries a signature counter, which Keyring stores in `sign_count`. If a key presents a counter lower than the last one seen, that suggests the key has been cloned. Keyring refuses that sign in and dispatches the `Keyring\Events\CloneSuspected` event. The event is logged, and it can send the `clone_suspected` [security email](security-log-and-emails.md#security-emails).

Synced passkeys usually report a counter of zero every time, so this check doesn't apply to them.

## Signing In Without a Username

Passkeys can sign in on their own, without a username:

1. The browser fetches `GET /login/passkey/options`, which answers with `{ "options": { ... } }`. The options have an empty `allowCredentials` and require user verification. Keyring keeps the challenge in the session.
2. The user picks a passkey, and the browser posts the response to `POST /login/passkey` as `credential`.
3. Keyring finds the passkey by its credential ID, among those belonging to the model behind its guard. It checks the signature, then continues with the [policy](policies.md), as it does for any login.

The same options also work for autofill, where the browser lists passkeys in the email field. To enable it, give the field `autocomplete="username webauthn"`. The browser package's `usePasskeyLogin({ autofill: true })` starts autofill for you. See [Frontend](frontend.md#signing-in-with-a-passkey). The client in Laravel's starter kits can also sign in through these two routes. See [Laravel's Passkeys Client](#laravels-passkeys-client).

A challenge works only once, and only for this kind of sign in. Trying it spends it, even if the sign in fails. It can't finish the second factor of a password login or a step-up, which use the challenge their own page issued. Spending a challenge removes it from the session and records, in the cache store your rate limits use (`cache.limiter`), that it was answered. That record refuses the same signed answer a second time when the session can't. This happens with an earlier copy of the session on Laravel's `cookie` session driver, or with a second request that arrived together with the first. The record is kept until the challenge would have expired. The same applies to a second factor's challenge, a step-up's challenge, and a new key's challenge. See [Known Limitations](security.md#known-limitations) for what that leaves.

Challenges also expire. The session they're kept in can last for days, so Keyring records when each challenge was issued. It refuses an answer that arrives more than `webauthn.login_options_for` later. That defaults to five minutes, and it's never less than `webauthn.timeout`. The other challenges don't need a clock of their own. A second factor's challenge and a step-up's are kept in the pending login, which ends after `pending_logins.keep_for` (10 minutes). A new key's challenge is kept in its enrollment, which ends after `enrollments.keep_for` (15 minutes).

With autofill, the login page asks for its options as it loads. The browser's own timeout doesn't apply while it waits for someone to pick a passkey. So a page left open for longer than `login_options_for` gets a challenge that has run out. That sign in fails like any refused passkey. The browser package then asks for new options straight away, and picking the passkey again works. If your users leave the login page open for a long time, raise `login_options_for`.

These requests don't name an account, so only the per-IP [rate limit](security.md#rate-limiting) applies. Junk requests can't fill a bucket that every user shares. Fetching the options has its own limit of 60 requests a minute per IP address, so a login page that reloads, or an office sharing one address, doesn't run out.

Security keys can't sign in this way. `/login/security-key` and `/login/security-key/options` return a `404`.

## Laravel's Passkeys Client

Keyring's passkey routes are driven by [`@keyringjs/keyring`](frontend.md). `@laravel/passkeys`, the client in Laravel's starter kits, is written for the routes of the `laravel/passkeys` Composer package. Each call lets you change its two paths, but not the method it uses or the JSON it reads. That's enough for signing in, which works against Keyring's two login routes. Adding a passkey and step-up don't fit. This was checked against `@laravel/passkeys` 0.2.0 and 0.4.1, and `laravel/passkeys` 0.3.0:

| What the Client Does | What Keyring Does |
|---|---|
| When signing in, it reads `options` from the JSON of `GET /passkeys/login/options`. | The same. `GET /login/passkey/options` answers `{ "options": { ... } }`. |
| It posts `{ credential, remember }` to `/passkeys/login` and reads `redirect`. | The same. `POST /login/passkey` answers `{ "status": "authenticated", "redirect": "..." }`. |
| When adding a passkey, it reads `options` from `GET /user/passkeys/options`. | Enrolling begins with a `POST` to `/user/authenticators/passkey`, and the options are under `enrollment.options`. |
| It posts `{ name, credential }` to `/user/passkeys`. `usePasskeyRegister()` doesn't pass the response on. | `POST /user/authenticators/passkey/confirm` takes those fields, but its response can carry [recovery codes](authenticators.md#recovery-codes) that are only shown once. |
| When confirming, it reads `options` from `GET /passkeys/confirm/options`. | [Step-up](step-up.md) has no options route. The confirm page gets the options as props, for whichever of the user's authenticators comes next. |

### Signing In With It

To use Keyring's login routes, pass them to the client:

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

The React and Vue hooks accept the same `routes`, for both the button and autofill:

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

There are a few things to keep in mind:

- Always send the user to `redirect`. It's the page the user was after, or the [challenge page](sign-in-flow.md#the-challenge-page) when your [policy](policies.md) asks for another factor after the passkey.
- A refused passkey answers with `422`, and a rate limit answers with `429`. The client throws either one with the message from the answer, and the hooks return that message as `error`. This also applies to autofill, so a login page reloaded past the options limit shows that message, where Keyring's own helper stays quiet.
- For autofill, the email field needs `autocomplete="username webauthn"`. The client expects a field whose `autocomplete` ends in `webauthn`.
- The `remember` option was added in `@laravel/passkeys` 0.4. Older versions leave it out, so the user isn't remembered.
- If you [changed the route prefix](configuration.md#routes), add it in front of both paths.

Every check is the same as in Keyring's own helper: the per-IP limits, the single-use challenge, and the policy.

### Adding a Passkey and Step-Up

Adding a passkey and step-up still need `@keyringjs/keyring`. Fitting the client would take a second set of routes for the same ceremonies, so Keyring doesn't try. To add a passkey, use [`enroll`](frontend.md#managing-authenticators). For the challenge and confirm pages, use [`useChallenge`](frontend.md#the-challenge-page). If you'd rather use one package for everything, [`usePasskeyLogin`](frontend.md#signing-in-with-a-passkey) signs in through the same two routes, as an Inertia visit. Passkeys made with `laravel/passkeys` keep working once you [import them](upgrading-from-fortify.md#importing-two-factor-data).

## Customising a Profile

You may register the same profile a second time under another factor key, for example to treat the hardware keys from one programme separately:

```php
WebAuthn::securityKeys()->as('backup-key'),
```

To require user verification for security keys, use:

```php
WebAuthn::securityKeys()->requireUserVerification(),
```

To accept only keys whose maker vouches for them, or only certain models (see [Attestation and AAGUIDs](#attestation-and-aaguids)), use:

```php
WebAuthn::securityKeys()->requireAttestation()->allowOnly([$aaguid]),
```

Each of these returns a new instance. A factor key other than `passkey` or `security-key` also needs a line in the frontend's [factor map](frontend.md#the-challenge-page). The browser package's `enroll` helper decides whether to run the WebAuthn ceremony from the options the server sends, so it works with any factor key:

```ts
import { enroll } from '@keyringjs/keyring'

await enroll('backup-key', { name: 'Spare key' })
```

To change more than the profile, extend the class. The `passkeys` and `securityKeys` methods return `static`, and the constructor is `final`, so they build your subclass:

```php
use Keyring\Factors\WebAuthn;

class AuditedWebAuthn extends WebAuthn
{
    // ...
}

Keyring::factors([AuditedWebAuthn::passkeys(), AuditedWebAuthn::securityKeys()]);
```

## Stored Data

Each key is stored as a row in the `keyring_authenticators` table, with these columns:

| Column | Holds |
|---|---|
| `credential_id` | The credential ID, in base64url without padding, up to 512 characters. Unique across all users. A key that sends a longer ID is refused at registration. |
| `public_key` | The full credential record as JSON, including the public key and counter. |
| `sign_count` | The last counter seen. |
| `aaguid` | The model identifier the key reported. |
| `attestation` | The kind of attestation checked against your roots when the key was added (`basic`). This is what vouches for `aaguid`. `null` when none was checked. |
| `transports` | How the browser can reach the key (`usb`, `nfc`, `internal`...). |
| `meta.user_verified` | Whether the key verified the user when registered. |
| `meta.backup_eligible` | Whether the key said it can be synced. |
| `meta.backed_up` | Whether the key said it has been backed up, which a key that can sync may not have been yet. Read again on every sign in, like `backup_eligible`. Keyring only records it: assurance goes by whether the key can sync at all. |

The user handle given to authenticators is an HMAC of the user's model (its morph class) and ID. The HMAC uses a key derived from `APP_KEY` for that purpose alone, and the handle is never the user's real ID or email. The model is part of the HMAC because an authenticator keeps one passkey per handle for a site. With two user models, a `User` 7 and a `Staff` 7 would otherwise share a handle, and a new passkey for one would replace the other's. Once a user has a key, new ones reuse its handle. This means that rotating `APP_KEY`, or adding a morph map later, doesn't make password managers list the account twice. A passkey imported from `laravel/passkeys` keeps the handle that package gave it.

To test passkeys without a browser, see the [VirtualAuthenticator](testing.md#virtual-authenticators) documentation.
