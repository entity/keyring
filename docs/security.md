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
- [Known Limitations](#known-limitations)

## Introduction

Keyring follows OWASP's authentication, session management and forgot password guidance, and NIST SP 800-63B's assurance levels. This page lists what it promises, so you can check your setup against it, and where it stops.

The [conformance suite](testing.md#the-conformance-suite) tests several of these guarantees against your own configuration.

## Guarantees

### Signing In

- A wrong password and an unknown account give the same error, on the same field, with the same status code.
- Every failed factor check takes at least `timebox` microseconds (250ms by default), and unknown accounts still run a password hash, so timing doesn't reveal which accounts exist.
- Pending logins are encrypted JSON in the session, never `serialize()`d, and expire after `pending_login_ttl`.
- The session ID is regenerated when a user signs in and when they step up.
- A password reset never signs anyone in, so the policy still applies at the next login.
- Keyring's responses send `Cache-Control: no-store, private`, and signing out sends `Clear-Site-Data`.

### Rate Limiting

Every factor has its own limits, checked in the pipeline before the proof is looked at:

- **Per account**: `limits.per_account` attempts a minute (5). Before the user is identified, the account is the typed username, lowercased and transliterated, so spelling variants of one address share a limit. After that, it's the user's ID.
- **Per IP address**: `limits.per_ip` attempts a minute (20), shared by every account on that address.

How they count:

- Each attempt is counted before it's verified, so overlapping requests can't all slip under the limit while they're being checked.
- When failures reach a limit, that key is locked. Each lock lasts twice as long as the one before (one minute, then two, then four...), up to a day. The count of lockouts resets a day after the first one.
- A success clears the account's count. On the per-IP count, a success only takes back its own attempt. People signing in from one office address don't use up its limit, and an attacker can't reset the limit by signing in to an account of their own between guesses.
- Requests that don't name an account, like usernameless passkey sign ins, only get the per-IP limit, so junk requests can't fill a bucket every user shares.

Factors can set their own limits by overriding `limits()`. Other routes use Laravel's throttle middleware: registration, password reset requests, resets, email change requests, enrollment confirmations, verification emails and the "this wasn't me" link are limited to 6 a minute, and the emailed email-change links to 12. Each pending attempt can send three codes per 10 minutes.

### Single-Use Codes

- TOTP codes can't be reused: each authenticator stores the last accepted time step, updated under a database row lock, so two requests with the same code can't both pass.
- Each recovery code works once, used up under the same kind of row lock. Two different codes used at the same time both stay valid until used.
- Email codes are random, eight digits, expire after 10 minutes, allow five wrong guesses, and are replaced by any newer code.
- WebAuthn challenges are random 32 byte values, kept on the server and dropped after one verification, so a response can't be replayed.

### Second Factors and Step-Up

- Policies count distinct categories, so two factors of the same kind are never treated as multi-factor.
- A passkey or security key only counts as inherence when it actually verified the user that time.
- With `noDowngrade()`, users with a passkey or security key can't be offered a weaker way in.
- Adding, removing or changing sign-in methods, revoking devices, changing the password and starting an email change need a fresh verification. Users with a possession factor must use one, so a stolen session plus a phished password isn't enough.
- The fresh window is fixed from the moment of verification and doesn't slide with activity.
- Users can't add a sign-in method until their email is verified (with `MustVerifyEmail`), so someone who registers an address first can't plant a factor that survives the real owner's password reset.
- Users can't remove authenticators below what they need to sign in.

### Sessions and Devices

- Every signed-in session is in Keyring's registry and is checked on every request, so revoking one takes effect on its next request with any session driver.
- Sessions have idle and absolute timeouts, which can be stricter at higher assurance levels.
- A session whose registry record has gone missing is signed out rather than started over.
- A revocation can't be undone by a request saving a stale copy of its session.
- Laravel's session ID is never stored by Keyring or written to the security log.
- Devices are recognised by a random, httpOnly cookie, stored as a hash. A device is never a factor, only an input to your policy and risk signals.

### Account Changes

- `email` and `password` can only change through Keyring's flows. Bypassing that needs `Keyring::withoutProtection()`, which is announced and logged.
- An email change needs a fresh verification, confirmation from the new address, and confirmation from the current address unless the session proved a second factor that existed before it signed in.
- An email change never reveals whether the new address has an account.
- An email change only applies if the address is still the one it was requested from.
- Emailed confirm and revert links only act on a button press (a POST), so mail scanners that open links can't confirm or revert anything.
- Reverting an email change signs out every session, closes later changes and removes sign-in methods added since.
- Password resets give the same answer for every address, sign out every session and cancel pending email changes.
- New passwords follow OWASP's length rules, are checked against breach lists, and are refused rather than silently cut short by bcrypt.

### Links and Headers

- Every emailed link (password reset, email change, email verification, "this wasn't me") is built from `APP_URL`, never from the request's `Host` header.
- Signed links are signed over the path and query only, and checked with `signed:relative`, so a forged `Host` header can't redirect them.
- The password reset page is sent with `Referrer-Policy: no-referrer`.

### Storage

- TOTP secrets are encrypted with `APP_KEY`.
- Recovery codes and email codes are stored as keyed hashes.
- Email change tokens are stored as SHA-256 hashes, and the addresses in a pending change are encrypted.
- Device tokens are stored as SHA-256 hashes.
- WebAuthn user handles are an HMAC of the user ID, never the ID or email.
- The security log never holds passwords, codes, tokens or session IDs.

## Known Limitations

- **Account lockouts can be triggered by anyone.** Per-account limits mean someone who knows a user's email can keep that account locked by typing wrong passwords. Locks double up to a day. A password reset doesn't lift them.
- **No attestation.** Any WebAuthn authenticator is accepted, and AAGUIDs aren't verified, so you can't restrict which key models users register. See [Attestation and AAGUIDs](passkeys.md#attestation-and-aaguids).
- **No clone detection for synced passkeys.** Their counters are usually always zero.
- **No downgrade has no recovery path.** With `noDowngrade()`, a user who loses their only passkey or security key isn't offered recovery codes and needs support's help. See [No Downgrade](policies.md#no-downgrade).
- **Session-held state isn't locked.** Pending email codes, their guess counts and WebAuthn challenges live in the session. Laravel doesn't lock sessions between concurrent requests by default, so parallel requests in one session can each spend a guess from the same count, or present the same response, within the rate limits. TOTP and recovery codes don't have this problem, since they're used up under a database lock.
- **Protection only covers Eloquent saves.** Query builder updates and `saveQuietly()` skip the protected attribute check.
- **Changing `APP_KEY` breaks hashed and encrypted data.** Recovery codes stop working, pending email codes become invalid, and the WebAuthn user handle for new keys changes. Laravel's previous keys only help with encrypted values such as TOTP secrets.
- **"Remember me" is all or nothing.** Laravel has one remember token per user, so revoking any device or signing out other sessions ends every remembered browser.
- **Location signals need trustworthy data.** `HeaderLocator` trusts request headers, so only use it behind a proxy that sets them and can't be bypassed.
- **The "this wasn't me" link acts on open.** Unlike the email change links, it has no confirmation button, so a mail scanner that opens it signs the device out.
- **After a JSON step-up, users return to `home`.** Keyring doesn't remember the page for `423` responses. See [JSON Requests](step-up.md#json-requests).
- **Session guards only.** Pending logins and step-up live in the session, so stateless API clients and mobile apps can't use the sign in flow directly.
- **Work in progress.** Keyring hasn't been tagged or used in production yet.
