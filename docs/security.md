# Security

- [Introduction](#introduction)
- [Guarantees](#guarantees)
    - [Signing In](#signing-in)
    - [Rate Limiting](#rate-limiting)
    - [Single-Use Codes](#single-use-codes)
    - [Second Factors and Step-Up](#second-factors-and-step-up)
    - [Sessions and Devices](#sessions-and-devices)
    - [Account Changes](#account-changes)
    - [Links and Headers](#links-and-headers)
    - [Storage](#storage)
- [Cryptography](#cryptography)
    - [Keys](#keys)
    - [Algorithms](#algorithms)
    - [Random Values](#random-values)
    - [Changing an Algorithm](#changing-an-algorithm)
    - [Peppering Passwords](#peppering-passwords)
- [What a Request Costs](#what-a-request-costs)
- [Standards](#standards)
- [Known Limitations](#known-limitations)

## Introduction

Keyring follows OWASP's authentication, session management and forgot password guidance, and NIST SP 800-63B's assurance levels. This page lists what it promises, so you can check your setup against it, and where it stops.

The [conformance suite](testing.md#the-conformance-suite) tests several of these guarantees against your own configuration.

Guarantees about a [feature](quick-start.md#adding-features), such as devices, email changes or the security log, apply once that feature is on.

## Guarantees

### Signing In

- A wrong password and an unknown account give the same error, on the same field, with the same status code.
- A sign-in only succeeds for a user Keyring's guard would load back through its provider. A passkey that belongs to another model (say, staff when the guard signs in users) fails like an unknown one, even when the IDs match.
- Every refused verification takes at least `timebox` (250ms by default), and unknown accounts still run a password hash, so timing doesn't reveal which accounts exist. The timebox is around the whole pipeline: the rate limits, the proof, the risk checks and whatever listens for a failure, so a `429` waits it out too. That includes a right password turned down by a risk lock or a risk response, which answers like a wrong one.
- A password longer than its stored hash can check (72 bytes for bcrypt) fails like a wrong one, with the same error, timing and throttling, wherever Keyring checks a password: signing in, step-up, removing the last second factor and the current password on a change. The over-long value never reaches the hasher.
- Passwords are put in Unicode's NFC form before they're measured, hashed or checked, so one set on a device that composes characters one way still works on a device that composes them another.
- Pending logins are encrypted JSON in the session, never `serialize()`d, and expire after `pending_logins.keep_for`, as soon as the user's password or email address changes, or when `keyring.guard` is no longer the guard they started under. An emailed code could have gone to the address the account no longer has, so an email change and its undo both end a sign in that was waiting for one.
- The session ID is regenerated and the old one destroyed when a user proves a factor (signing in or stepping up), changes their password or signs out everywhere else, so a copied session cookie stops working, and someone who planted a session ID before the password step doesn't share the pending login.
- A password reset never signs anyone in, so the policy still applies at the next login.
- Checking a password can rehash it under the app's current settings. The new hash is only saved over the one that was checked, under a row lock, so a sign in that overlaps a reset can't write the old password back, and whatever device trust it was given is withdrawn when it's ended.
- A login attempt can't sign the owner out. Risk responses at login never revoke sessions, change the "remember me" token or stop trusting devices, even from a custom responder.
- Keyring's responses send `Cache-Control: no-store, private` and `Referrer-Policy: same-origin`, and signing out sends `Clear-Site-Data`.

### Rate Limiting

Every factor has its own limits, checked in the pipeline before the proof is looked at:

- **Per account**: `limits.per_account` attempts a minute (5). The account is the user: Keyring finds who a typed username belongs to before it counts, so every way of typing it shares one limit, guesses at login and when confirming count together, and two accounts never share a count however alike their usernames look. Browsers the account has signed in from before (they carry one of its device cookies) count in a bucket of their own, so someone guessing from elsewhere can't lock the owner out (OWASP's "device cookies"). They share that one bucket between them: a device cookie is made at every sign in from a new browser, so someone who could once sign in may hold any number, and with a bucket each they'd get the account's allowance of guesses once per cookie. A browser stops counting as known when a password reset or change, or a sign-out everywhere, takes the account back, until it signs in again.
- **Per typed username**: a sign in that names its account is counted under the name as typed as well, with the same numbers, whether or not anyone has it. Only this count says so when it refuses (the `429`). The account's own limit refuses quietly: the attempt is answered like a wrong password, in the same time, without the password being looked at. So a name is answered from its own history, and locking an account under one name doesn't show which other names belong to it, or which names have an account at all.
- **Per IP address**: `limits.per_ip` attempts a minute (20), shared by every account on that address. A browser carrying the account's device cookie counts per IP for that account alone, so others on a shared address can't hold it up, and an attacker holding several of the account's device cookies still gets one count. Behind a load balancer, configure Laravel's trusted proxies, or every user shares the balancer's address.
- **In a row**: `limits.consecutive` failures (100, as NIST SP 800-63B caps them) on one account's factor, however slowly they come. Only a success clears the count, or a password reset for the factors that can start a sign in. At the cap that factor is refused for the account, though the user can still sign in with another factor; `null` turns the cap off. Without it, guessing just under the per-minute limit would never stop. With `Features::devices()` on, browsers the account has signed in from before share a count of their own, so guesses made elsewhere can't use it up. A second factor at the cap stays refused for up to 30 days (`limits.remember_failures_for`). Until then it works from a known browser, or the user signs in with another factor or a recovery code.

How they count:

- Each attempt is counted before it's verified, so overlapping requests can't all slip under the limit while they're being checked.
- Routes that spend session state (sign in, challenge pages and verifications, enrollment) take Laravel's session lock (`->block()`), so parallel requests in one session can't reuse a WebAuthn challenge or run two verifications of one pending sign in at once. Your cache store must support locks, as the database, Redis, file and array stores do. A sent code doesn't depend on that lock: it's [used up in the cache](#single-use-codes).
- When failures reach an account's limit, that key is locked. Each lock lasts twice as long as the one before (one minute, then two, then four...), up to a day (`limits.longest_lock`). The count of lockouts resets a day after the first one.
- The per-IP limit locks the same way, but never for longer than 15 minutes (`limits.longest_ip_lock`). One person failing behind a shared address (carrier-grade NAT, an office) holds the others up for a quarter of an hour at most, while someone spraying passwords from one address still slows to about `limits.per_ip` guesses every 15 minutes. A browser carrying the account's device cookie isn't held up, and an attempt the address refuses doesn't count against the account. With `Features::devices()` off, everyone on the address waits.
- A success clears the account's count. On the per-IP count, a success only takes back its own attempt. People signing in from one office address don't use up its limit, and an attacker can't reset either limit by signing in to an account of their own between guesses, even one whose username differs from the victim's by an accent.
- A completed password reset clears the account's in-a-row counts, per-minute counts, locks and lockout count on the factors that can start a sign in, with those of each of its known devices and of every name they were typed under, so the owner can sign in straight away. Second factors keep their counts and locks, because a reset only proves control of the mailbox and could otherwise be repeated to keep guessing a code. The `password_reset` log entry records it. Per-IP limits stay, so a reset can't be used to get around them.
- Requests that don't name an account, like usernameless passkey sign ins, only get the per-IP limit, so junk requests can't fill a bucket every user shares.

All of this is counted in the cache store Laravel's rate limiter uses (`cache.limiter`, or your default store), and [risk locks](risk.md#actions) in `risk.store`. A count that's gone reads as no attempts, so if the store loses its keys every limit starts over and every lock lifts: `php artisan cache:clear` and `optimize:clear` empty the default store, and a store that evicts under memory pressure can drop them one at a time. Where the in-a-row cap and the locks have to hold, point `cache.limiter` and `risk.store` at a persistent store of their own that doesn't evict and that your deploys don't clear.

#### Locking Until a Reset

By default every lock lifts by itself, the longest after a day. To stop the guessing altogether, set `limits.lock_after`:

```php
'limits' => [
    'lock_after' => 5,
],
```

An account locked that many times within a day on a factor that can start a sign in then stays locked. Locks double, so with the default one-minute window the fifth comes after about a quarter of an hour of steady guessing and at most eleven fit in a day: a higher number never holds anything. The sign-in form says to reset the password (`keyring::keyring.locked`) in place of counting down, and Keyring dispatches `AccountLocked` and logs `account_locked`. Register the [`account_locked` notice](security-log-and-emails.md#email-types) to email the owner that the account is locked and that resetting the password unlocks it. Like every security notice it isn't sent until you register it.

The lock ends with a completed password reset, with `Keyring::unlock($user)` from a support tool of your own, or when failures are forgotten after `limits.remember_failures_for` (30 days), so raise that to hold it for longer. Like every limit it's kept in the cache, so see the note above about a store that doesn't lose its keys.

It follows the other limits' rules. Browsers the account has signed in from before have their own count and keep working, so the owner isn't locked out of a browser they already use. A name nobody has locks the same way and gets the same answer. Second factors are never held, because a password reset wouldn't clear them: they keep the in-a-row cap. That includes security keys, which only ever come second. A hold placed by wrong passwords on a confirm page, by a signed-in session, lands on the account's own limit, which the sign-in form refuses quietly: there the right password is answered as wrong, with no hint that a reset would help, so tell the user with the `account_locked` notice, or from `AccountLocked` yourself.

This is off by default because it lets anyone who knows a username lock that account for everyone on a new browser until its owner resets the password.

Factors can set their own limits by overriding `limits()`. A reset only clears the keys the default `limits()` builds, so a factor with its own per-account keys should clear them in a `PasswordReset` listener. Other routes use Laravel's throttle middleware with the named `keyring` limiter: registration, password reset requests, resets, password changes, email change requests, enrollment confirmations, removing an authenticator, verification emails, the emailed email-change links and the "this wasn't me" link share 6 requests a minute per user, or per IP address for guests. Usernameless passkey options have their own limiter, `keyring-login-options`, at 60 requests a minute per IP address, because the login page fetches them on every load for autofill. Apps can redefine either limiter (see [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits)). Each account can be sent three codes per factor every 10 minutes (`limits.codes` and `limits.codes_per`), however many sign ins, step-ups or enrollments ask for them.

Mail that isn't a guess at anything has a count of its own, since a sign in that succeeds is never counted and the form limiter only counts the sender. An account is sent each kind of [security notice](security-log-and-emails.md#security-emails) five times an hour at most (`limits.notices` and `limits.notices_per`), with every event still in the security log. An account can ask to change its email address that often, and a typed address is mailed about a change that often, whichever accounts ask. No security notice goes to a `MustVerifyEmail` user whose address isn't verified: whoever registered typed it, so it may be anyone's.

### Single-Use Codes

- TOTP codes can't be reused: each authenticator stores the last accepted time step, updated under a database row lock, so two requests with the same code can't both pass.
- A TOTP code is accepted one 30 second step either side of now at most, and only during its own step with a [window of zero](factors.md#authenticator-apps-totp). No wider window can be set.
- Each recovery code works once, used up under the same kind of row lock. Two different codes used at the same time both stay valid until used.
- Email codes are random, eight digits (shown as two groups of four, `1234 5678`; spaces are ignored), expire after 10 minutes, allow five wrong guesses per pending attempt, and are replaced by any newer code. A newer code doesn't reset the count, and at the limit the user has to start signing in again. A sent code only verifies the authenticator it was sent to.
- No factor that sends codes, the built-in email codes or [one of your own](factors.md#writing-a-code-factor), can be registered with codes shorter than six digits or that last longer than ten minutes. Keyring throws a `LogicException` instead.
- A sent code works once on every session driver. Its state isn't in the session: the code waiting to be typed (as a keyed hash), the wrong guesses at it and the fact that it was used are kept in the cache store the rate limits use (`cache.limiter`), under the pending sign in, step-up or enrollment it was sent for. A right code is used up the moment it's checked, even when a later step refuses the sign in, and of two requests that send it together one is refused. A newer code ends the one before it, and the guesses stay counted, whichever copy of the session the browser sends. That goes for every code factor, at sign in, step-up and enrollment. If that cache store is cleared, pending codes go with it and the user asks for another.
- An enrollment adds its sign-in method once. That it was confirmed is remembered in the same cache store until it would have expired, so an earlier copy of the session can't confirm it again and bring back recovery codes that have since been replaced or used.
- WebAuthn challenges are random 32 byte values, kept on the server and dropped on the first verification, whether it succeeds or not, so a response can't be replayed. If a passkey verifies on the second-factor step and a later check such as a risk lock refuses the login, the challenge stays with that pending login until it expires. A challenge only completes the ceremony it was issued for: one from the usernameless login options can't finish a second factor or a step-up.
- A passkey's signature counter is checked and saved under the same kind of row lock, so two assertions can't both pass against one stored count, and a slower request can't lower it.

### Second Factors and Step-Up

- Policies count distinct categories, so two factors of the same kind are never treated as multi-factor.
- Assurance levels follow NIST SP 800-63B: a passkey that syncs reaches AAL2, and AAL3 needs a phishing-resistant key that can't leave its device, read from the flag the key reports on every sign in.
- Email codes are opt-in (`EmailCode::asSecondFactor()`), since NIST rules out email for authentication codes and the inbox can also reset the password.
- A passkey or security key only counts as inherence when it actually verified the user that time.
- With `noDowngrade()`, users with a passkey or security key can't be offered a weaker way in. Recovery codes stay on offer as the way back in, unless you pass `except: []`.
- With `ifEnrolled()`, a policy the user can't fully meet still asks for the strongest version they can give, so a user with a second factor never signs in with one factor.
- Adding, removing or changing sign-in methods, revoking devices, changing the password and starting an email change need a fresh verification of everything signing in would ask for (NIST SP 800-63B's rule for binding authenticators). Users with a possession factor always use one, so a stolen session plus one phished factor isn't enough.
- The fresh window is fixed from the moment of verification and doesn't slide with activity.
- Users can't add a sign-in method until their email is verified (with `MustVerifyEmail`), so someone who registers an address first can't plant a factor that survives the real owner's password reset. With registration on, a user model that can't verify its email can't add sign-in methods at all.
- Users can't remove authenticators below what they need to sign in, even with several removals at once.

### Sessions and Devices

- Every signed-in Keyring route checks Keyring's guard (`auth:{guard}`), and the step-up middleware reads the user from it, so another guard's user can't stand in.
- Every signed-in session is in Keyring's registry and is checked on every `web` request (and any other group you add `keyring.session` to), so revoking one takes effect on its next request with any session driver.
- Sessions have idle and absolute timeouts, and each assurance level lapses on NIST SP 800-63B's clock (AAL2: 1 hour idle or 24 hours; AAL3: 15 minutes or 12 hours) until the user verifies again.
- "Remember me" can't outlast the session it was ticked for. Laravel's cookie alone signs nobody in: the browser also holds a Keyring cookie naming that session's registry record, and coming back carries the session on with the limits it started with and nothing proved. Once the record has timed out, been revoked or been ended by a risk response, both cookies are refused, even from a client that kept them after being told to delete them.
- A "remember me" cookie works once. Coming back moves the session to a new record and gives the browser a new cookie, so a copy of the pair brings back nothing the browser it was taken from hasn't already had. If a used cookie is sent again, or a browser is still signed in on the record it named, two browsers held the same pair: the session ends for both, with a `RememberMeReused` event and a `remember_me_reused` log entry. The one exception is the same browser's other requests in the few seconds after (`sessions.remember_grace`), which join the session the first one resumed. They can't start another, and sending the cookie again doesn't make those seconds any longer.
- A resumed session's device, IP address and browser are those of the request that resumed it, on a record of its own. A browser still on the record from before is never compared with them.
- A session whose registry record has gone missing is signed out rather than started over.
- A revocation can't be undone by a request saving a stale copy of its session.
- Laravel's session ID is never stored by Keyring or written to the security log.
- Devices are recognised by a random, httpOnly cookie, stored as a hash. A device is never a factor, only an input to your policy and risk signals.
- Signing out everywhere also stops trusting the other devices and cancels pending email changes, so whoever had the account can't skip the second factor on a device they trusted or finish a change they started.
- A device is only trusted after a login that verified two categories, never after the password alone. A login that verifies two categories, and any grant of trust, gives the browser a new cookie, so neither can rest on a cookie planted in the browser before the user signed in.
- Every device stops being trusted when the password changes, an authenticator is removed, an email change is applied or a signed-in request places a risk lock. A lock placed by a login attempt doesn't, as above.

### Account Changes

- With `Features::updatePasswords()` and `Features::emailChanges()` on, `password` and `email` can only change through Keyring's flows. Bypassing that needs `Keyring::withoutProtection()`, which is announced and logged. Without them, your app changes those attributes itself.
- An email change needs a fresh verification, confirmation from the new address, and confirmation from the current address unless the session proved a second factor the account has had for a week (`email_changes.established_after`) and since before it signed in.
- An email change never reveals whether the new address has an account, in its answer, its timing or the pending change it shows: its emails, like the reset email, are sent after the response.
- An email change only applies if the address is still the one it was requested from.
- Emailed links (email change confirm and revert, and "this wasn't me") only act on a button press (a POST), so mail scanners that open links change nothing.
- A password reset with a bad token gets the same answer for every address. Password rules, which are shorter for accounts with MFA, only run once the token checks out.
- Reverting an email change signs out every session, ends any sign in still waiting for its second factor, closes later changes and removes sign-in methods that weren't established when it was asked for. Cancelling a change doesn't stop its revert link working.
- While an email change can be reverted, nobody else can take the address it replaced, so the revert always has somewhere to put it back.
- Password resets give the same answer for every address, sign out every session, cancel pending email changes, and lift risk locks and sign-in lockouts.
- A password change takes the current password as well as a fresh verification, checked by Keyring itself rather than by your action. A user with no password yet sets one with the fresh verification alone.
- Password changes cancel pending email changes, so someone who knew the old password can't finish one.
- New passwords need at least 8 characters with a second factor and 15 without, and neither minimum can be configured below 8. Any characters are accepted, with no composition rules.
- New passwords are checked against the 10,000 most common of 8 characters or more and the 3,000 most common of 15 or more, in every environment, and against your app's name, the words you list in `passwords.context` and the user's own name and email address, with look-alike characters read as letters. The whole password is compared, as NIST SP 800-63B-4 Sec. 3.1.1.2 requires: one made up of those words is refused, and a passphrase that only has one in it is not.
- In production, new passwords are also checked against breach lists (Have I Been Pwned). That check lets a password through when the service can't be reached, unless you set `passwords.refuse_unchecked`.
- New passwords are refused rather than silently cut short by bcrypt. With bcrypt that limit is 72 bytes, so hash with argon2id to accept every password up to `passwords.max`.

### Links and Headers

- Every emailed link (password reset, email change, email verification, "this wasn't me") is built from `APP_URL`, never from the request that caused the email: not its `Host` header, and not an `X-Forwarded-Prefix` your proxy passed on.
- Signed links are signed over the path and query only, and checked with `signed:relative`, so a forged `Host` header can't redirect them.
- Pages opened from emailed links (password resets, email changes, "this wasn't me") keep their token out of the `Referer` header other sites see, like every Keyring response. Your own app still receives it, so a failed form finds its way back.

#### Emailed Links

An app on several domains can start the links somewhere other than `APP_URL`, such as the tenant the user belongs to:

```php
Keyring::linkRootUsing(fn () => tenant()->url);
```

Work it out from something the server knows. The request's `Host` header is whatever the sender says, and a link built from it sends a real reset token to their site. The signature covers the path and query, so links keep working under any root.

### Storage

- TOTP secrets are encrypted with `APP_KEY`. [Cryptography](#cryptography) lists every algorithm and key.
- Recovery codes and email codes are stored as keyed hashes (HMAC-SHA-256). A recovery code is only stored with 112 random bits or more: Keyring's own have 128, those imported from Fortify 119, and no other form is stored or accepted. A sent code is far shorter, so its hash is kept in your cache for ten minutes at most and allowed five guesses.
- Keyed hashes never use `APP_KEY` itself. Each kind (recovery codes, one-time codes, reserved addresses, WebAuthn user handles) has a key of its own, derived from `APP_KEY` with HKDF, so a hash made for one can't pass as another and none is made with the key Laravel encrypts and signs with.
- Email change tokens are stored as SHA-256 hashes, and the addresses in a pending change are encrypted.
- Device tokens are stored as SHA-256 hashes.
- WebAuthn credential IDs longer than 512 characters are refused rather than cut short.
- WebAuthn user handles are an HMAC of the user ID, never the ID or email.
- The security log never holds passwords, codes, tokens or session IDs.

## Cryptography

Everything Keyring does with a key or an algorithm, and where. It adds no cipher or hash of its own: each one below is PHP's, Laravel's or a library's.

### Keys

| Key | Where it lives | Used for |
|---|---|---|
| `APP_KEY`, and `APP_PREVIOUS_KEYS` for what was made before a rotation | Your environment | Laravel's encrypter and signed URLs, directly. Keyring never uses it as a key of its own. |
| Four purpose keys, one each for recovery codes, one-time codes, reserved addresses and WebAuthn user handles | Nowhere: derived on each use from `APP_KEY` (and each previous key) with HKDF-SHA-256, the purpose's name as the label | Keyring's keyed hashes. A hash made for one purpose can't pass as another, and none is made with the key that encrypts. |
| Each authenticator app's TOTP secret, 160 random bits | `keyring_authenticators.secret`, encrypted | Making and checking that app's codes. |
| Each passkey's or security key's public key | `keyring_authenticators.public_key`, as the key sent it | Checking that key's signatures. The private key never leaves the authenticator. |
| Attestation root certificates | Your `webauthn.attestation_roots`, or your `TrustsAuthenticators` | Deciding which makers' keys a factor with `requireAttestation()` takes. |
| The password hash | Your `users` table | Laravel's hasher: see below. |

Rotating `APP_KEY` with the old key in `APP_PREVIOUS_KEYS` keeps encrypted values, signed links, recovery codes and reserved addresses working. See [Known Limitations](#known-limitations) for the short-lived values it ends.

### Algorithms

| Algorithm | Where | What it protects |
|---|---|---|
| Laravel's encrypter, with your `app.cipher`: AES-256-CBC with an HMAC-SHA-256 tag by default, or AES-256-GCM | The `secret` of an authenticator (TOTP secrets, the set of recovery code hashes, whatever a code factor of yours keeps there); `value` and `previous_value` of a pending change (both addresses); pending logins and enrollments in the session, whatever the session driver | Secrets and addresses at rest. |
| Laravel's cookie encryption, the same cipher | The device cookie and the "remember me" pairing cookie, when your `web` group encrypts cookies, as it does by default | Tokens in the browser. |
| HMAC-SHA-256 under a purpose key | Recovery codes; emailed codes, and those of your own code factors, while they wait in the cache to be typed; the lookup hash of an address an email change holds; the WebAuthn user handle | Values that are only ever compared or looked up, never read back. |
| SHA-256, unkeyed | Device tokens and email change tokens (confirm, current address, revert) | Long random tokens, so a copy of the table can't be used as one. Each has well over 128 bits, which is why a plain hash is enough. |
| SHA-256, unkeyed | The mark a pending login keeps of the user's password hash and address, inside the encrypted session | Noticing that either changed. Not a secret. |
| HMAC-SHA-1, or HMAC-SHA-256 or HMAC-SHA-512 where the factor is [set up with one](factors.md#authenticator-apps-totp) | TOTP codes (RFC 6238), six digits every 30 seconds | A legacy algorithm in OWASP ASVS's terms, kept as the default because it's the one every authenticator app makes. |
| Laravel's hash manager, with your `hashing.driver`: bcrypt by default, or Argon2id | Passwords, the hash an unknown account spends, and the reset tokens Laravel's broker stores | Keyring calls `Hash` and never picks the algorithm or its cost. |
| ECDSA with P-256 and SHA-256 (ES256), Ed25519 (EdDSA), and RSASSA-PKCS1-v1_5 with SHA-256 (RS256, off by default, 2048 bits at least) | Signatures from passkeys and security keys, limited to [`webauthn.algorithms`](passkeys.md#signature-algorithms) | Proof of holding the key. SHA-256 also hashes the client data and the relying party ID, as WebAuthn defines. |
| X.509 path validation: ECDSA, Ed25519, Ed448 or RSASSA-PKCS1-v1_5 signatures over SHA-224 or longer, RSA keys of 2048 bits at least, never SHA-1 | Attestation chains, only for a factor with [`requireAttestation()`](passkeys.md#requiring-attestation) | Which maker's key this is. The algorithms are whatever the maker signed its certificates with, so this accepts RSA with PKCS #1 v1.5 padding, which ASVS doesn't approve: several makers' roots use it. Off by default. |
| HMAC-SHA-256 with `APP_KEY`, by Laravel's URL signing | The email verification link and the "this wasn't me" link | That the link was made by your app, for that route, and hasn't expired. |
| SHA-1, unkeyed | The address in Laravel's email verification link; shortening the cache keys of the rate limits, sent codes and enrollments; and the breached-password lookup, where Have I Been Pwned's API is asked by the first five characters of a SHA-1 | Nothing rests on it: the link is signed as above, a cache key isn't a secret, and the lookup is the API's own format, whether Laravel makes it or Keyring does (`passwords.refuse_unchecked`). |

### Random Values

All of it comes from the operating system's generator, through PHP's `random_bytes()` and `random_int()`. `Str::random()` is built on `random_bytes()`. Nothing uses `rand()`, `mt_rand()` or `uniqid()`.

| Value | Made with | Size |
|---|---|---|
| Recovery codes | `random_bytes(16)` | 128 bits each |
| WebAuthn challenges | `random_bytes(32)` | 256 bits |
| TOTP secrets | `random_int()`, 32 base32 characters | 160 bits |
| Device tokens | `Str::random(40)` | About 238 bits |
| Session registry IDs, one of which is the "remember me" pairing | `Str::random(40)` | About 238 bits |
| Pending login IDs, enrollment IDs and the reference a sent code is kept under | `Str::random(40)` | About 238 bits |
| Email change tokens | `Str::random(48)` | About 285 bits |
| Laravel's "remember me" token, when Keyring replaces it | `Str::random(60)` | About 357 bits |
| WebAuthn user handles | HMAC-SHA-256 of the user's ID under a purpose key, not random | 256 bits, and not guessable without `APP_KEY` |
| Emailed codes | `random_int()` | Eight digits, about 27 bits. Short on purpose: they last 10 minutes and five guesses. |
| The password an unknown account's hash is spent on | `Str::random(32)` | Thrown away. |

### Changing an Algorithm

| To change | How | What happens to stored values |
|---|---|---|
| The password hash or its cost | `hashing.driver` and its options | Nothing to re-make: each password is rehashed the next time its owner signs in. |
| `APP_KEY` | Set the new key, with the old one in `APP_PREVIOUS_KEYS` | Encrypted values are read with the old key and written with the new one as they're next saved. Recovery codes and reserved addresses are found under either. A sent code waiting to be typed stops working, and the user asks for another. |
| The cipher | `app.cipher` | Laravel only reads what the current cipher wrote, so every authenticator secret and pending change has to be decrypted and saved again in a migration of your own before the old cipher goes. Pending logins and enrollments end. |
| The WebAuthn algorithms | `webauthn.algorithms` and `webauthn.minimum_rsa_bits` | Adding one changes nothing stored. Removing one refuses the keys that sign with it, and their owners add a new key: a key's algorithm can't be changed. |
| The TOTP digest | The factor's `algorithm` | Only apps added afterwards use it. An authenticator keeps the digest it was set up with, so moving everyone means each user adding their app again. |
| The keyed hash (HMAC-SHA-256) or how its keys are derived | Fixed in code | A new release would have to re-make them: reserved address hashes can be recomputed from the encrypted address, recovery codes can't be (only the hash is kept) and would be issued again, and a WebAuthn user handle stays for as long as the user has a key that knows it. Stored hashes carry no version tag. |
| The token hash (SHA-256) | Fixed in code | Tokens can't be rehashed, since only the hash is kept. Device cookies and pending email change links would be issued again. |

### Peppering Passwords

NIST SP 800-63B suggests, beyond the salted hash, a keyed hash or encryption of it under a secret kept apart from the database, often called a pepper. Keyring doesn't build one in, for three reasons. The password hash is your `users.password` column and Laravel's hasher, shared with everything else in your app that checks a password, so a pepper only Keyring knew about would break those. A pepper is only worth having when its key lives somewhere the database's attacker can't reach, and where that is (an HSM, a secrets manager, at least a separate environment variable) is your infrastructure's decision. And losing or rotating it locks out every user at once, so it needs a plan that belongs to whoever runs the app.

Keyring checks and sets passwords through Laravel's `Hash`, so a pepper goes in there and covers every flow: signing in, confirming, password changes, resets and the rehash at sign in. Register a driver that wraps the one you use now:

```php
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\Hash;

class PepperedHasher implements Hasher
{
    public function __construct(
        protected Hasher $hasher,
        #[\SensitiveParameter] protected string $pepper,
    ) {}

    public function make(#[\SensitiveParameter] $value, array $options = []): string
    {
        return $this->hasher->make($this->pepper($value), $options);
    }

    public function check(#[\SensitiveParameter] $value, $hashedValue, array $options = []): bool
    {
        return $this->hasher->check($this->pepper($value), $hashedValue, $options);
    }

    public function info($hashedValue): array
    {
        return $this->hasher->info($hashedValue);
    }

    public function needsRehash($hashedValue, array $options = []): bool
    {
        return $this->hasher->needsRehash($hashedValue, $options);
    }

    // Base64, because a raw HMAC can hold a NUL byte, where bcrypt stops reading.
    protected function pepper(#[\SensitiveParameter] string $value): string
    {
        return base64_encode(hash_hmac('sha256', $value, $this->pepper, true));
    }
}

// In a service provider's boot().
Hash::extend('peppered', fn () => new PepperedHasher(
    Hash::driver('argon2id'),
    config('services.password_pepper'),
));
```

Then set `hashing.driver` to `peppered`. Three things to settle first:

- **Existing passwords.** A hash made without the pepper won't match with it. Either have `check()` fall back to the bare hasher and report `needsRehash()` for those, so each moves over at its owner's next sign in, or add the pepper before there are users.
- **Rotation.** Changing the pepper is changing every hash. Keep the old one to check against, and rehash on sign in, as above.
- **Length.** The HMAC is 44 characters whatever was typed, so bcrypt's 72 byte limit no longer cuts a long password short. Keyring's [password rules](protected-changes.md#password-rules) go by `hashing.driver`, so with a driver that isn't `bcrypt` they stop refusing passwords over 72 bytes. A password over 72 bytes is still refused at sign in while its stored hash is a bcrypt one, since Keyring can't tell a peppered bcrypt hash from a plain one: wrap Argon2id rather than bcrypt, or keep new passwords to 72 bytes with a rule of your own.

## What a Request Costs

The operations below are the expensive ones, each with what stops a stranger from running it without limit. All of it happens inside a request: Keyring starts no background work except the emails noted.

| Operation | When | What bounds it |
|---|---|---|
| One password hash (bcrypt or Argon2id, at your cost setting) | Every password attempt the limits let through, including for a name with no account, which spends a hash on a random password so both take the same time | The [rate limits](#rate-limiting) are checked first, and a refused attempt hashes nothing: 5 a minute per account and per typed name, 20 a minute per IP address, with locks that double. The account's own limit refuses quietly, and that refusal still spends a hash so it takes as long as a wrong password, until the typed name's limit or the IP address's answers with a `429`. Hashing a new password on registration, a change or a reset is behind the `keyring` limiter, 6 a minute. |
| A worker held for `timebox` (250ms) | Every refused verification, a `429` included | It's a sleep, not CPU, but it does hold a PHP worker, and Keyring doesn't bound how many: a rate-limited request waits like any other refusal, or the limits would show in the timing. What bounds it sits in front of PHP: the connection and request limits of your web server or load balancer, and the size of the worker pool. Lowering `timebox` gives each worker back sooner and makes timing less even. |
| The breached-password lookup, an HTTPS request to Have I Been Pwned | Setting a password, in production by default (`passwords.uncompromised`); and at every password sign in if you add the `BreachedPassword` risk signal, which isn't on by default | Behind the `keyring` limiter for new passwords, and the sign-in limits for the signal. Laravel's verifier gives up after 30 seconds and then lets the password through, so an outage slows these requests rather than failing them. With `passwords.refuse_unchecked`, Keyring asks itself, gives up after 10 seconds and refuses the password. Turn the check off, or bind an `UncompromisedVerifier` of your own with a shorter timeout, if that's too long to hold a worker. |
| WebAuthn verification: decoding the response and checking one signature | Adding a key, and every sign in or step-up with one | At sign in, the factor's rate limits, checked before the response is read; adding a key is behind the `keyring` limiter and a fresh verification. Usernameless options are limited to 60 a minute per IP address. An RSA key is bounded to 16,384 bits by the library, since the work grows with the key. |
| Attestation: a certificate chain of at most six, checked against each root you list for the model | Adding a key to a factor with `requireAttestation()` | The `keyring` limiter on enrollment, the cap on chain length, and nothing being fetched: no revocation lookups, no metadata download. |
| Mail | A reset link, an email change, a verification link, an emailed code, a security notice | Reset and email-change mail is sent after the response. A verification link and an emailed code are sent during the request, unless you queue those notifications: a code is limited to three per factor every 10 minutes per account (`limits.codes`). The published security notices are queued, five of a kind an hour per account (`limits.notices`). The routes that ask for mail are behind the `keyring` limiter. |
| A session lock | Sign in, challenge and enrollment routes | Requests in one session wait for each other, for up to Laravel's 10 seconds, and one that waited that long fails. One session can't hold up another. |

## Standards

Keyring's code and config say what each thing does. This is where the choices come from:

| What Keyring does | From |
|---|---|
| Assurance levels, and what reaches AAL2 and AAL3 | NIST SP 800-63B |
| Each level lapsing after idle and overall limits (AAL2: 1 hour, 24 hours; AAL3: 15 minutes, 12 hours) | NIST SP 800-63B, reauthentication |
| A cap of 100 failures in a row on an account's factor | NIST SP 800-63B, rate limiting |
| Proving the account's factors again before adding a sign-in method | NIST SP 800-63B, binding an authenticator |
| Passkeys and security keys as a phishing-resistant option | NIST SP 800-63B |
| Email codes being opt-in, and below AAL2 | NIST SP 800-63B, which rules out email for authentication codes |
| The four emails `keyring:install` offers: password changed, sign-in method added or removed, recovery code used | NIST SP 800-63B, and OWASP's Authentication Cheat Sheet |
| A notice after each change to how someone signs in, once registered: the password, a sign-in method added or removed, new recovery codes, the email address | OWASP ASVS 5.0.0, 6.3.7 |
| A notice of a suspicious attempt, once registered: a new device, a failed second factor, a locked account, and what the risk signals find, such as a sign in after a long quiet period or after several failures | OWASP ASVS 5.0.0, 6.3.5 |
| Password lengths: 8 with a second factor, 15 without, and no setting below 8 | OWASP ASVS 5.0.0, 6.2.1, and NIST SP 800-63B (15 for a password used alone, 8 as part of multi-factor) |
| A password change taking the current password as well as the new one | OWASP ASVS 5.0.0, 6.2.3 |
| Refusing the most common passwords: the top 10,000 of 8 characters or more and the top 3,000 of 15 or more | OWASP ASVS 5.0.0, 6.2.4 (at least the top 3,000 that fit the policy) |
| No composition rules, and any characters accepted | OWASP ASVS 5.0.0, 6.2.5, and NIST SP 800-63B |
| Passwords of at least 64 characters allowed, never silently cut short: up to `passwords.max` with argon2id, 72 bytes with bcrypt | OWASP ASVS 5.0.0, 6.2.9, and NIST SP 800-63B. Met with `HASH_DRIVER=argon2id`, not with bcrypt |
| Refusing passwords made up of the app's name, the words in `passwords.context`, or the user's name and email address, comparing the whole password | OWASP ASVS 5.0.0, 6.2.11, with 6.1.2 for the list, which is yours to fill in; NIST SP 800-63B-4 Sec. 3.1.1.2 for comparing the whole password |
| Refusing breached passwords, in production by default | OWASP ASVS 5.0.0, 6.2.12, and NIST SP 800-63B |
| Passwords of any Unicode characters, normalized to NFC before hashing | NIST SP 800-63B, password verifiers |
| Two factors of the same kind not counting as two, and no weaker fallback for a user with a phishing-resistant factor | OWASP's Multifactor Authentication Cheat Sheet |
| Making everyone add a second factor with `keyring.enrolled` | OWASP ASVS 6.3.3 |
| Locks that double each time, and a count of its own for the browsers the account has signed in from | OWASP's Authentication Cheat Sheet and its "device cookies" guidance |
| Single-use codes: random, short-lived, limited guesses, stored hashed, a resend replacing the last | OWASP's Authentication Cheat Sheet |
| TOTP codes, recovery codes and sent codes that work once, whatever the session driver | OWASP ASVS 5.0.0, 6.5.1 |
| Recovery codes with at least 112 random bits, which is what lets them be kept as keyed hashes rather than salted password hashes | OWASP ASVS 5.0.0, 6.5.2 |
| Sent codes of at least six digits | OWASP ASVS 5.0.0, 6.5.4 |
| Sent codes that last ten minutes at most | OWASP ASVS 5.0.0, 6.5.5 |
| TOTP codes accepted one time step either side of now, and no further | RFC 6238, section 5.2. This default deviates from OWASP ASVS 5.0.0, 6.5.5 (a 30 second maximum), which a window of zero meets: see [Known Limitations](#known-limitations) |
| Password resets: the same answer for every address, links built from `APP_URL`, no automatic sign in, every session signed out | OWASP's Forgot Password Cheat Sheet |
| Email changes confirmed from both addresses, and not trusting an address that just changed | OWASP's Authentication and Multifactor Authentication Cheat Sheets |
| A recent verification before changing how someone signs in | OWASP's Authentication Cheat Sheet |
| Never caching auth pages and responses | OWASP's Session Management Cheat Sheet |
| A "remember me" cookie that works once, with a used one ending the session | OWASP's Session Management Cheat Sheet, and refresh token rotation with reuse detection (RFC 9700) |

## Known Limitations

- **Lockouts still reach new browsers.** Someone who knows a user's email can keep that account locked by guessing faster than the per-minute limit. If they guess under one of the account's names and the owner types another, the owner is told the password is wrong rather than to wait, because saying more would tell a stranger the two names are one account. With `Features::devices()` on, browsers the owner has signed in from before keep their own limit and keep working. Without devices, the lock reaches every browser while the guessing goes on. A password reset clears the password's counts and locks, but not a second factor's.
- **By default a TOTP code works for longer than OWASP ASVS allows.** ASVS 5.0.0 requirement 6.5.5 gives a time-based one-time password a maximum lifetime of 30 seconds. Keyring accepts a code one time step either side of now unless told otherwise, so one code can work for up to about 90 seconds, and as shipped it does not meet that requirement. The default follows RFC 6238 (section 5.2), which recommends allowing one step for clock drift and delay: with none, a code typed near the end of its 30 seconds fails, and so does every code from a phone whose clock is half a minute out. A code still works only once. To meet 6.5.5 exactly, register the factor with [a window of zero](factors.md#authenticator-apps-totp). A window wider than one step is refused.
- **Windows Hello keys that only sign RS256 aren't taken by default.** RS256 isn't an algorithm OWASP ASVS approves, so `webauthn.algorithms` leaves it out, and on a machine whose Windows Hello makes nothing else, a passkey can't be created with it. See [RS256 and Windows Hello](passkeys.md#rs256-and-windows-hello) for who that affects and how to turn it on.
- **Attestation is off unless you ask for it, and only covers hardware keys.** By default any WebAuthn authenticator is accepted and AAGUIDs aren't verified. A factor set up with `requireAttestation()` checks `packed` and `fido-u2f` attestation against root certificates you list, and can then be limited to certain models. Platform formats (`tpm`, `android-key`, `apple`) aren't read, and certificates aren't looked up for revocation. See [Attestation and AAGUIDs](passkeys.md#attestation-and-aaguids).
- **No clone detection for synced passkeys.** Their counters are usually always zero.
- **Protection only covers Eloquent saves.** Query builder updates and `saveQuietly()` skip the protected attribute check.
- **Changing `APP_KEY` invalidates short-lived data.** Pending email codes stop working, and a user's first passkey after the change gets a different user handle (later ones reuse the handle their keys already have). Recovery codes and reserved email addresses keep working when the old key is in `APP_PREVIOUS_KEYS`, as encrypted values such as TOTP secrets do.
- **Signing out ends "remember me" in every browser.** Laravel has one remember token per user, so signing out, revoking any device or signing out other sessions ends every remembered browser. A session that times out, or that Keyring ends for another reason, only ends its own.
- **A copied "remember me" pair is only caught when both holders use it.** Whoever comes back first gets the session, and it ends when the other one turns up: with the used cookie, or still signed in on the old record. A copy made of a browser that never comes back is not noticed, and lasts until the session's `absolute` limit. Inside `sessions.remember_grace` a copy sent from what looks like the same browser joins the session instead, and is caught the next time either of them comes back. A browser that never received the response carrying its new cookie looks like a copy the next time, and has to sign in again.
- **"Remember me" expects one session store per browser.** Two apps that share the cookies and the registry but keep separate Laravel sessions would each see the other's return as a used cookie.
- **Laravel's `cookie` session driver can't destroy an old session.** The session lives in the cookie, so a copied one keeps working after the ID changes, until the session is revoked or expires. Signing out everywhere else, a password change and an applied email change revoke the session's registry record and carry on under a new one, so a copy is signed out then. After a step-up it keeps working, without what the step-up proved. Use a server-side session driver if that matters.
- **The `cookie` session driver lets a browser send back what its session held.** With that driver the session lives in the browser, so it can send an earlier copy of its own cookie, and a pending login or enrollment is kept in the session. Nothing that must happen only once depends on it. TOTP steps and recovery codes are used up in your database. A sent code, its wrong guesses, the code that replaced it and each enrollment's one confirmation are kept in your cache, with the limits on attempts per account and per IP address, failures in a row and codes sent. Two things an earlier copy still brings back. It returns a pending sign in or step-up to an earlier point, which only means proving a factor again. And it still holds a WebAuthn challenge that was already answered, so whoever has both that copy and the signed answer the key gave could send the answer again. A key that counts its signatures refuses it, because the count hasn't moved on. A synced passkey, whose count stays at zero, is accepted a second time, for as long as that copy of the session lasts. A server-side session driver closes both.
- **A request overlapping a session ID change can undo or lose it.** Laravel saves the session when each request ends, so a request still running when the ID changes can save the old session again, and a copied cookie would then keep working. A request sent with the old ID just after the change finds no session, and that browser has to sign in again.
- **The breach check fails open by default.** Laravel's check lets a new password through when Have I Been Pwned can't be reached, leaving the bundled list of common passwords. Set `passwords.refuse_unchecked` to refuse the password instead, at the cost of no new passwords while the service is unreachable. Outside production the check doesn't run at all unless `passwords.uncompromised` is `true`.
- **Bcrypt stops passwords at 72 bytes.** It's Laravel's default hasher, and it ignores everything after the first 72 bytes, so with it Keyring refuses a longer password: 72 plain characters, but as few as 18 emoji, whatever `passwords.max` says. OWASP ASVS 6.2.9 asks for at least 64 characters, of any kind, to be allowed. Set `HASH_DRIVER=argon2id` for that. Keyring doesn't pre-hash passwords to fit, which would leave hashes Laravel's own hasher can't check. See [Passwords](configuration.md#passwords).
- **Location signals need trustworthy data.** `HeaderLocator` trusts request headers, so only use it behind a proxy that sets them and can't be bypassed.
- **Session guards only.** Pending logins and step-up live in the session, so stateless API clients and mobile apps can't use the sign in flow directly.
- **Work in progress.** Keyring hasn't been tagged or used in production yet.
