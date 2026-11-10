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
- Every refused verification takes at least `timebox` (250ms by default), and unknown accounts still run a password hash, so timing doesn't reveal which accounts exist. That includes a right password turned down by a risk lock or a risk response, which answers like a wrong one.
- A password longer than its stored hash can check (72 bytes for bcrypt) fails like a wrong one, with the same error, timing and throttling, wherever Keyring checks a password: signing in, step-up, removing the last second factor and the current password on a change. The over-long value never reaches the hasher.
- Pending logins are encrypted JSON in the session, never `serialize()`d, and expire after `pending_logins.keep_for`, as soon as the user's password changes, or when `keyring.guard` is no longer the guard they started under.
- The session ID is regenerated and the old one destroyed when a user proves a factor (signing in or stepping up), changes their password or signs out everywhere else, so a copied session cookie stops working, and someone who planted a session ID before the password step doesn't share the pending login.
- A password reset never signs anyone in, so the policy still applies at the next login.
- A login attempt can't sign the owner out. Risk responses at login never revoke sessions, change the "remember me" token or stop trusting devices, even from a custom responder.
- Keyring's responses send `Cache-Control: no-store, private` and `Referrer-Policy: no-referrer`, and signing out sends `Clear-Site-Data`.

### Rate Limiting

Every factor has its own limits, checked in the pipeline before the proof is looked at:

- **Per account**: `limits.per_account` attempts a minute (5). For the factors that can start a sign in (the password, passkeys), the account is the username, lowercased and transliterated, so spelling variants of one address share a limit, and guesses at login and when confirming count together. For second factors, it's the user's ID. A browser the account has signed in from before (it carries the account's device cookie) counts in a bucket of its own, so someone guessing from elsewhere can't lock the owner out (OWASP's "device cookies").
- **Per IP address**: `limits.per_ip` attempts a minute (20), shared by every account on that address. A browser carrying the account's device cookie counts per IP for that account alone, so others on a shared address can't hold it up, and an attacker holding several of the account's device cookies still gets one count. Behind a load balancer, configure Laravel's trusted proxies, or every user shares the balancer's address.
- **In a row**: `limits.consecutive` failures (100, as NIST SP 800-63B caps them) on one account's factor, however slowly they come. Only a success clears the count, or a password reset for the factors that can start a sign in. At the cap that factor is refused for the account, though the user can still sign in with another factor; `null` turns the cap off. Without it, guessing just under the per-minute limit would never stop. With `Features::devices()` on, a browser the account has signed in from before keeps a count of its own, so guesses made elsewhere can't use it up. A second factor at the cap stays refused for up to 30 days (`limits.remember_failures_for`). Until then it works from a known browser, or the user signs in with another factor or a recovery code.

How they count:

- Each attempt is counted before it's verified, so overlapping requests can't all slip under the limit while they're being checked.
- Routes that spend session state (sign in, challenge pages and verifications, enrollment) take Laravel's session lock (`->block()`), so parallel requests in one session can't reuse an email code's guesses or a WebAuthn challenge. Your cache store must support locks, as the database, Redis, file and array stores do.
- When failures reach an account's limit, that key is locked. Each lock lasts twice as long as the one before (one minute, then two, then four...), up to a day (`limits.longest_lock`). The count of lockouts resets a day after the first one.
- The per-IP limit locks the same way, but never for longer than 15 minutes (`limits.longest_ip_lock`). One person failing behind a shared address (carrier-grade NAT, an office) holds the others up for a quarter of an hour at most, while someone spraying passwords from one address still slows to about `limits.per_ip` guesses every 15 minutes. A browser carrying the account's device cookie isn't held up, and an attempt the address refuses doesn't count against the account. With `Features::devices()` off, everyone on the address waits.
- A success clears the account's count. On the per-IP count, a success only takes back its own attempt. People signing in from one office address don't use up its limit, and an attacker can't reset the limit by signing in to an account of their own between guesses.
- A completed password reset clears the account's in-a-row counts, per-minute counts, locks and lockout count on the factors that can start a sign in, under the account's `username` attribute, the user's ID and each of the account's known devices, so the owner can sign in straight away. Second factors keep their counts and locks, because a reset only proves control of the mailbox and could otherwise be repeated to keep guessing a code. The `password_reset` log entry records it. Per-IP limits stay, so a reset can't be used to get around them. If a custom [`findUsersUsing()`](sign-in-flow.md#finding-the-user) also accepts something else, like a username next to the email address, failures typed under that are only cleared if the app says so.
- Requests that don't name an account, like usernameless passkey sign ins, only get the per-IP limit, so junk requests can't fill a bucket every user shares.

Factors can set their own limits by overriding `limits()`. A reset only clears the keys the default `limits()` builds, so a factor with its own per-account keys should clear them in a `PasswordReset` listener. Other routes use Laravel's throttle middleware with the named `keyring` limiter: registration, password reset requests, resets, password changes, email change requests, enrollment confirmations, removing an authenticator, verification emails, the emailed email-change links and the "this wasn't me" link share 6 requests a minute per user, or per IP address for guests. Usernameless passkey options have their own limiter, `keyring-login-options`, at 60 requests a minute per IP address, because the login page fetches them on every load for autofill. Apps can redefine either limiter (see [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits)). Each account can be sent three codes per factor every 10 minutes (`limits.codes` and `limits.codes_per`), however many sign ins, step-ups or enrollments ask for them.

### Single-Use Codes

- TOTP codes can't be reused: each authenticator stores the last accepted time step, updated under a database row lock, so two requests with the same code can't both pass.
- Each recovery code works once, used up under the same kind of row lock. Two different codes used at the same time both stay valid until used.
- Email codes are random, eight digits (shown as two groups of four, `1234 5678`; spaces are ignored), expire after 10 minutes, allow five wrong guesses per pending attempt, and are replaced by any newer code. A newer code doesn't reset the count, and at the limit the user has to start signing in again. A sent code only verifies the authenticator it was sent to.
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
- Sessions have idle and absolute timeouts, and each assurance level lapses on NIST SP 800-63B's clock (AAL2: 1 hour idle or 24 hours; AAL3: 15 minutes or 12 hours) until the user verifies again. The "remember me" cookie lasts no longer than a session.
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
- Reverting an email change signs out every session, closes later changes and removes sign-in methods that weren't established when it was asked for. Cancelling a change doesn't stop its revert link working.
- While an email change can be reverted, nobody else can take the address it replaced, so the revert always has somewhere to put it back.
- Password resets give the same answer for every address, sign out every session, cancel pending email changes, and lift risk locks and sign-in lockouts.
- Password changes cancel pending email changes, so someone who knew the old password can't finish one.
- New passwords follow OWASP's length rules, are checked against the most common passwords and, in production, against breach lists, and are refused rather than silently cut short by bcrypt.

### Links and Headers

- Every emailed link (password reset, email change, email verification, "this wasn't me") is built from `APP_URL`, never from the request's `Host` header.
- Signed links are signed over the path and query only, and checked with `signed:relative`, so a forged `Host` header can't redirect them.
- Pages opened from emailed links (password resets, email changes, "this wasn't me") keep their token out of the `Referer` header, like every Keyring response.

#### Emailed Links

An app on several domains can start the links somewhere other than `APP_URL`, such as the tenant the user belongs to:

```php
Keyring::linkRootUsing(fn () => tenant()->url);
```

Work it out from something the server knows. The request's `Host` header is whatever the sender says, and a link built from it sends a real reset token to their site. The signature covers the path and query, so links keep working under any root.

### Storage

- TOTP secrets are encrypted with `APP_KEY`.
- Recovery codes and email codes are stored as keyed hashes.
- Email change tokens are stored as SHA-256 hashes, and the addresses in a pending change are encrypted.
- Device tokens are stored as SHA-256 hashes.
- WebAuthn credential IDs longer than 512 characters are refused rather than cut short.
- WebAuthn user handles are an HMAC of the user ID, never the ID or email.
- The security log never holds passwords, codes, tokens or session IDs.

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
| Password lengths (8 with a second factor, 15 without), no composition rules, breached passwords refused, nothing silently cut short | NIST SP 800-63B and OWASP's Authentication Cheat Sheet |
| Refusing the most common passwords, and ones containing the app's or user's name | OWASP ASVS |
| Two factors of the same kind not counting as two, and no weaker fallback for a user with a phishing-resistant factor | OWASP's Multifactor Authentication Cheat Sheet |
| Making everyone add a second factor with `keyring.enrolled` | OWASP ASVS 6.3.3 |
| Locks that double each time, and a count of their own for browsers the account has signed in from | OWASP's Authentication Cheat Sheet and its "device cookies" guidance |
| Single-use codes: random, short-lived, limited guesses, stored hashed, a resend replacing the last | OWASP's Authentication Cheat Sheet |
| Password resets: the same answer for every address, links built from `APP_URL`, no automatic sign in, every session signed out | OWASP's Forgot Password Cheat Sheet |
| Email changes confirmed from both addresses, and not trusting an address that just changed | OWASP's Authentication and Multifactor Authentication Cheat Sheets |
| A recent verification before changing how someone signs in | OWASP's Authentication Cheat Sheet |
| Never caching auth pages and responses | OWASP's Session Management Cheat Sheet |

## Known Limitations

- **Lockouts still reach new browsers.** Someone who knows a user's email can keep that account locked by guessing faster than the per-minute limit. With `Features::devices()` on, browsers the owner has signed in from before keep their own limit and keep working. Without devices, the lock reaches every browser while the guessing goes on. A password reset clears the password's counts and locks, but not a second factor's.
- **No attestation.** Any WebAuthn authenticator is accepted, and AAGUIDs aren't verified, so you can't restrict which key models users register. See [Attestation and AAGUIDs](passkeys.md#attestation-and-aaguids).
- **No clone detection for synced passkeys.** Their counters are usually always zero.
- **Protection only covers Eloquent saves.** Query builder updates and `saveQuietly()` skip the protected attribute check.
- **Changing `APP_KEY` invalidates short-lived data.** Pending email codes stop working, and a user's first passkey after the change gets a different user handle (later ones reuse the handle their keys already have). Recovery codes and reserved email addresses keep working when the old key is in `APP_PREVIOUS_KEYS`, as encrypted values such as TOTP secrets do.
- **"Remember me" is all or nothing.** Laravel has one remember token per user, so signing out, revoking any device or signing out other sessions ends every remembered browser. A session that times out only forgets its own.
- **Laravel's `cookie` session driver can't destroy an old session.** The session lives in the cookie, so a copied one keeps working after the ID changes, until the session is revoked or expires. Signing out everywhere else, a password change and an applied email change revoke the session's registry record and carry on under a new one, so a copy is signed out then. After a step-up it keeps working, without what the step-up proved. Use a server-side session driver if that matters.
- **The `cookie` session driver can replay what a session held.** A pending login or enrollment is kept in the session, so a browser can send back an earlier copy of its own cookie: one from before a code's guesses were counted, say. The limits that stop guessing don't live there. Attempts per account and per IP address, failures in a row, and codes sent are counted in your cache, so a replayed cookie doesn't get more guesses than the limits allow. A server-side session driver closes the gap entirely.
- **A request overlapping a session ID change can undo or lose it.** Laravel saves the session when each request ends, so a request still running when the ID changes can save the old session again, and a copied cookie would then keep working. A request sent with the old ID just after the change finds no session, and that browser has to sign in again.
- **Location signals need trustworthy data.** `HeaderLocator` trusts request headers, so only use it behind a proxy that sets them and can't be bypassed.
- **Session guards only.** Pending logins and step-up live in the session, so stateless API clients and mobile apps can't use the sign in flow directly.
- **Work in progress.** Keyring hasn't been tagged or used in production yet.
