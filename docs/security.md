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

Guarantees about a [feature](quick-start.md#adding-features), such as devices, email changes or the security log, apply once that feature is on.

## Guarantees

### Signing In

- A wrong password and an unknown account give the same error, on the same field, with the same status code.
- A sign-in only succeeds for a user Keyring's guard would load back through its provider. A passkey that belongs to another model (say, staff when the guard signs in users) fails like an unknown one, even when the IDs match.
- Every failed factor check takes at least `timebox` microseconds (250ms by default), and unknown accounts still run a password hash, so timing doesn't reveal which accounts exist.
- A password longer than its stored hash can check (72 bytes for bcrypt) fails like a wrong one, with the same error, timing and throttling, wherever Keyring checks a password: signing in, step-up, removing the last second factor and the current password on a change. The over-long value never reaches the hasher.
- Pending logins are encrypted JSON in the session, never `serialize()`d, and expire after `pending_login_ttl`, as soon as the user's password changes, or when `keyring.guard` is no longer the guard they started under.
- The session ID is regenerated and the old one destroyed when a user proves a factor (signing in or stepping up), changes their password or signs out everywhere else, so a copied session cookie stops working, and someone who planted a session ID before the password step doesn't share the pending login.
- A password reset never signs anyone in, so the policy still applies at the next login.
- A login attempt can't sign the owner out. Risk responses at login never revoke sessions, change the "remember me" token or stop trusting devices, even from a custom responder.
- Keyring's responses send `Cache-Control: no-store, private`, and signing out sends `Clear-Site-Data`.

### Rate Limiting

Every factor has its own limits, checked in the pipeline before the proof is looked at:

- **Per account**: `limits.per_account` attempts a minute (5). Before the user is identified, the account is the typed username, lowercased and transliterated, so spelling variants of one address share a limit. After that, it's the user's ID. A browser the account has signed in from before (it carries the account's device cookie) counts in a bucket of its own, so someone guessing from elsewhere can't lock the owner out (OWASP's "device cookies").
- **Per IP address**: `limits.per_ip` attempts a minute (20), shared by every account on that address.
- **In a row**: `limits.consecutive` failures (100, as NIST SP 800-63B caps them) on one account's factor, however slowly they come. Only a success clears the count, or a password reset for the factors that can start a sign in. At the cap that factor is refused for the account, though the user can still sign in with another factor; `null` turns the cap off. Without it, guessing just under the per-minute limit would never stop. With `Features::devices()` on, a browser the account has signed in from before keeps a count of its own, so guesses made elsewhere can't use it up. A second factor at the cap stays refused for up to 30 days. Until then it works from a known browser, or the user signs in with another factor or a recovery code.

How they count:

- Each attempt is counted before it's verified, so overlapping requests can't all slip under the limit while they're being checked.
- Routes that spend session state (sign in, challenge pages and verifications, enrollment) take Laravel's session lock (`->block()`), so parallel requests in one session can't reuse an email code's guesses or a WebAuthn challenge. Your cache store must support locks, as the database, Redis, file and array stores do.
- When failures reach a limit, that key is locked. Each lock lasts twice as long as the one before (one minute, then two, then four...), up to a day. The count of lockouts resets a day after the first one.
- A success clears the account's count. On the per-IP count, a success only takes back its own attempt. People signing in from one office address don't use up its limit, and an attacker can't reset the limit by signing in to an account of their own between guesses.
- A completed password reset clears the account's in-a-row counts, per-minute counts, locks and lockout count on the factors that can start a sign in, under the account's `username` attribute, the user's ID and each of the account's known devices, so the owner can sign in straight away. Second factors keep their counts and locks, because a reset only proves control of the mailbox and could otherwise be repeated to keep guessing a code. The `password_reset` log entry records it. Per-IP limits stay, so a reset can't be used to get around them. If a custom [`findUsersUsing()`](sign-in-flow.md#finding-the-user) also accepts something else, like a username next to the email address, failures typed under that are only cleared if the app says so.
- Requests that don't name an account, like usernameless passkey sign ins, only get the per-IP limit, so junk requests can't fill a bucket every user shares.

Factors can set their own limits by overriding `limits()`. A reset only clears the keys the default `limits()` builds, so a factor with its own per-account keys should clear them in a `PasswordReset` listener. Other routes use Laravel's throttle middleware with the named `keyring` limiter: registration, password reset requests, resets, password changes, email change requests, enrollment confirmations, verification emails, the emailed email-change links and the "this wasn't me" link share 6 requests a minute per user, or per IP address for guests. Usernameless passkey options have their own limiter, `keyring-login-options`, at 60 requests a minute per IP address, because the login page fetches them on every load for autofill. Apps can redefine either limiter (see [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits)). Each account can be sent three codes per factor every 10 minutes, however many sign ins, step-ups or enrollments ask for them.

### Single-Use Codes

- TOTP codes can't be reused: each authenticator stores the last accepted time step, updated under a database row lock, so two requests with the same code can't both pass.
- Each recovery code works once, used up under the same kind of row lock. Two different codes used at the same time both stay valid until used.
- Email codes are random, eight digits, expire after 10 minutes, allow five wrong guesses per pending attempt, and are replaced by any newer code. A newer code doesn't reset the count, and at the limit the user has to start signing in again. A sent code only verifies the authenticator it was sent to.
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
- Sessions have idle and absolute timeouts, and each assurance level lapses on NIST SP 800-63B's clock (AAL2: 1 hour idle or 24 hours; AAL3: 15 minutes or 12 hours) until the user verifies again. "Remember me" lasts no longer than a session.
- A session whose registry record has gone missing is signed out rather than started over.
- A revocation can't be undone by a request saving a stale copy of its session.
- Laravel's session ID is never stored by Keyring or written to the security log.
- Devices are recognised by a random, httpOnly cookie, stored as a hash. A device is never a factor, only an input to your policy and risk signals.
- Signing out everywhere also stops trusting the other devices and cancels pending email changes, so whoever had the account can't skip the second factor on a device they trusted or finish a change they started.

### Account Changes

- With `Features::updatePasswords()` and `Features::emailChanges()` on, `password` and `email` can only change through Keyring's flows. Bypassing that needs `Keyring::withoutProtection()`, which is announced and logged. Without them, your app changes those attributes itself.
- An email change needs a fresh verification, confirmation from the new address, and confirmation from the current address unless the session proved a second factor that existed before it signed in.
- An email change never reveals whether the new address has an account, in its answer, its timing or the pending change it shows: its emails, like the reset email, are sent after the response.
- An email change only applies if the address is still the one it was requested from.
- Emailed links (email change confirm and revert, and "this wasn't me") only act on a button press (a POST), so mail scanners that open links change nothing.
- A password reset with a bad token gets the same answer for every address. Password rules, which are shorter for accounts with MFA, only run once the token checks out.
- Reverting an email change signs out every session, closes later changes and removes sign-in methods added since the session that asked for it signed in. Cancelling a change doesn't stop its revert link working.
- While an email change can be reverted, nobody else can take the address it replaced, so the revert always has somewhere to put it back.
- Password resets give the same answer for every address, sign out every session, cancel pending email changes, and lift risk locks and sign-in lockouts.
- Password changes cancel pending email changes, so someone who knew the old password can't finish one.
- New passwords follow OWASP's length rules, are checked against the most common passwords and, in production, against breach lists, and are refused rather than silently cut short by bcrypt.

### Links and Headers

- Every emailed link (password reset, email change, email verification, "this wasn't me") is built from `APP_URL`, never from the request's `Host` header.
- Signed links are signed over the path and query only, and checked with `signed:relative`, so a forged `Host` header can't redirect them.
- The password reset page is sent with `Referrer-Policy: no-referrer`.

### Storage

- TOTP secrets are encrypted with `APP_KEY`.
- Recovery codes and email codes are stored as keyed hashes.
- Email change tokens are stored as SHA-256 hashes, and the addresses in a pending change are encrypted.
- Device tokens are stored as SHA-256 hashes.
- WebAuthn credential IDs longer than 512 characters are refused rather than cut short.
- WebAuthn user handles are an HMAC of the user ID, never the ID or email.
- The security log never holds passwords, codes, tokens or session IDs.

## Known Limitations

- **Lockouts still reach new browsers.** Someone who knows a user's email can keep that account locked by guessing faster than the per-minute limit. With `Features::devices()` on, browsers the owner has signed in from before keep their own limit and keep working. Without devices, the lock reaches every browser while the guessing goes on. A password reset clears the password's counts and locks, but not a second factor's.
- **No attestation.** Any WebAuthn authenticator is accepted, and AAGUIDs aren't verified, so you can't restrict which key models users register. See [Attestation and AAGUIDs](passkeys.md#attestation-and-aaguids).
- **No clone detection for synced passkeys.** Their counters are usually always zero.
- **Protection only covers Eloquent saves.** Query builder updates and `saveQuietly()` skip the protected attribute check.
- **Changing `APP_KEY` invalidates short-lived data.** Pending email codes stop working, and new passkeys get a different user handle. Recovery codes and reserved email addresses keep working when the old key is in `APP_PREVIOUS_KEYS`, as encrypted values such as TOTP secrets do.
- **"Remember me" is all or nothing.** Laravel has one remember token per user, so revoking any device or signing out other sessions ends every remembered browser.
- **Laravel's `cookie` session driver can't destroy an old session.** The session lives in the cookie, so a copied one keeps working after the ID changes, until the session is revoked or expires. Signing out everywhere else, a password change and an applied email change revoke the session's registry record and carry on under a new one, so a copy is signed out then. After a step-up it keeps working, without what the step-up proved. Use a server-side session driver if that matters.
- **A request overlapping a session ID change can undo or lose it.** Laravel saves the session when each request ends, so a request still running when the ID changes can save the old session again, and a copied cookie would then keep working. A request sent with the old ID just after the change finds no session, and that browser has to sign in again.
- **Location signals need trustworthy data.** `HeaderLocator` trusts request headers, so only use it behind a proxy that sets them and can't be bypassed.
- **Session guards only.** Pending logins and step-up live in the session, so stateless API clients and mobile apps can't use the sign in flow directly.
- **Work in progress.** Keyring hasn't been tagged or used in production yet.
