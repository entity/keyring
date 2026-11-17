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
    - [Request Input](#request-input)
    - [Storage](#storage)
    - [Logging](#logging)
- [What Keyring Keeps](#what-keyring-keeps)
- [What Your App Must Provide](#what-your-app-must-provide)
    - [HTTPS and HSTS](#https-and-hsts)
    - [Trusted Proxies](#trusted-proxies)
    - [Secure Cookies](#secure-cookies)
    - [A Content Security Policy](#a-content-security-policy)
    - [Headers on Your Other Responses](#headers-on-your-other-responses)
    - [Bot Checks](#bot-checks)
- [Cryptography](#cryptography)
    - [Keys](#keys)
    - [Algorithms](#algorithms)
    - [Random Values](#random-values)
    - [Changing an Algorithm](#changing-an-algorithm)
    - [Peppering Passwords](#peppering-passwords)
- [What a Request Costs](#what-a-request-costs)
- [Standards](#standards)
- [Known Limitations](#known-limitations)
    - [Where Keyring Departs From a Standard](#where-keyring-departs-from-a-standard)
    - [Other Limits](#other-limits)

## Introduction

Keyring is built on OWASP ASVS 5.0.0, OWASP's cheat sheets on authentication, and NIST SP 800-63B-4. Its assurance levels follow NIST SP 800-63B-4 as far as a library can check. This page lists what it promises, so you can check your setup against it, and where it stops: [Standards](#standards) says where each choice comes from, and [Known Limitations](#known-limitations) where Keyring does something other than a standard says.

The [conformance suite](testing.md#the-conformance-suite) tests several of these guarantees against your own configuration. [OWASP ASVS and NIST SP 800-63B](owasp-asvs.md) goes through ASVS 5.0.0 requirement by requirement, says what to turn on for each of its levels, and what your app has to supply for each of NIST's.

Guarantees about a [feature](quick-start.md#adding-features), such as devices or email changes, apply once that feature is on.

## Guarantees

### Signing In

- A wrong password and an unknown account give the same error, on the same field, with the same status code.
- A sign-in only succeeds for a user Keyring's guard would load back through its provider. A passkey that belongs to another model (say, staff when the guard signs in users) fails like an unknown one, even when the IDs match.
- Every refused verification takes at least `timebox` (500ms by default), and unknown accounts still run a password hash, so timing doesn't reveal which accounts exist. A hash for a name with no account is made at today's cost, where an account's is checked at its stored hash's, so the wait is what covers the difference, and it only can while it's [longer than a hash takes](configuration.md#pending-logins-timebox-and-rate-limits). A refused password reset is held for it too. The timebox is around the whole pipeline: the rate limits, the proof, the risk checks and whatever listens for a failure, so a `429` waits it out too. That includes a right password turned down by a risk lock or a risk response, which answers like a wrong one.
- A password longer than its stored hash can check (72 bytes for bcrypt) fails like a wrong one, with the same error, timing and throttling, wherever Keyring checks a password: signing in, step-up, removing the last second factor and the current password on a change. The over-long value never reaches the hasher.
- Passwords are put in Unicode's NFC form before they're measured, hashed or checked, so one set on a device that composes characters one way still works on a device that composes them another.
- Pending logins are encrypted JSON in the session, never `serialize()`d, and expire after `pending_logins.keep_for`, as soon as the user's password or email address changes, as soon as a sign-in method they've already proved is removed from the account (by its owner, or by an undone email change), or when `keyring.guard` is no longer the guard they started under. An emailed code could have gone to the address the account no longer has, so an email change and its undo both end a sign in that was waiting for one.
- The session ID is regenerated and the old one destroyed when a user proves a factor (signing in or stepping up), changes their password or signs out everywhere else, so a copied session cookie stops working, and someone who planted a session ID before the password step doesn't share the pending login. On Laravel's `cookie` session driver, where there is nothing on the server to destroy, the old copy is signed out through its registry record instead.
- A password reset never signs anyone in, so the policy still applies at the next login.
- Registration doesn't reveal whether an address has an account, unless you set `registration.reveal_taken`. A free address, a taken one, one reserved for its previous owner and one whose account you keep out get the same response, status, cookies and session, after the same validation, in at least `timebox`, with one password hash each and every email sent after the response. Nobody is signed in by registering. Whether an address is taken is decided by Keyring, not by your action, so the guarantee doesn't depend on how the action is written, as long as it doesn't check for itself. See [Registration](sign-in-flow.md#without-revealing-who-has-an-account).
- With that registration, an account can't be signed in until its address is verified, and a correct password is answered like a wrong one until then. Verifying takes the emailed link and the password together, so neither someone who registered an address they can't read mail for, nor its owner who never chose that password, ends up with a verified account. A finished password reset also verifies the address.
- Checking a password can rehash it under the app's current settings. The new hash is only saved over the one that was checked, under a row lock, so a sign in that overlaps a reset can't write the old password back, and whatever device trust it was given is withdrawn when it's ended.
- A login attempt can't sign the owner out. Risk responses at login never revoke sessions, change the "remember me" token or stop trusting devices, even from a custom responder.

### Rate Limiting

Every factor has its own limits, checked in the pipeline before the proof is looked at:

- **Per account**: `limits.per_account` attempts a minute (5). The account is the user: Keyring finds who a typed username belongs to before it counts, so every way of typing it shares one limit, guesses at login and when confirming count together, and two accounts never share a count however alike their usernames look. Browsers the account has signed in from before (they carry one of its device cookies) count in a bucket of their own, so someone guessing from elsewhere can't lock the owner out, an idea taken from the OWASP Community page on device cookies. They share that one bucket between them: a device cookie is made at every sign in from a new browser, so someone who could once sign in may hold any number, and with a bucket each they'd get the account's allowance of guesses once per cookie. A browser stops counting as known when a password reset or change, or a sign-out everywhere, takes the account back, until it signs in again.
- **Per typed username**: a sign in that names its account is counted under the name as typed as well, with the same numbers, whether or not anyone has it. Only this count says so when it refuses (the `429`). The account's own limit refuses quietly: the attempt is answered like a wrong password, in the same time, without the password being looked at. So a name is answered from its own history, and locking an account under one name doesn't show which other names belong to it, or which names have an account at all. Nothing that happens to the account changes what its name answers either: after a password reset, a new password or `Keyring::unlock()`, a name that was refused goes on being refused to anyone without the password, as a name with no account would. The owner still gets in: behind a refused name the account's own limits decide whether the password is looked at, the right one signs in, and a wrong one is answered as the name was. Only a factor that finds its user by the username counts under it. A passkey goes by its credential, so a username sent along with one counts against nobody.
- **Per IP address**: `limits.per_ip` attempts a minute (20), shared by every account on that address. A browser carrying the account's device cookie counts per IP for that account alone, so others on a shared address can't hold it up, and an attacker holding several of the account's device cookies still gets one count. Behind a load balancer, configure Laravel's [trusted proxies](#trusted-proxies), or every user shares the balancer's address.
- **In a row**: `limits.consecutive` failures (100, the most NIST SP 800-63B-4 allows, Sec. 3.2.2) on one of an account's authenticators, however slowly they come. Each authenticator app, security key and set of recovery codes has a count of its own, and so does the password. They're counted in the database, so clearing the cache doesn't start them over, and at the cap the authenticator is refused for the account until that's dealt with: nothing brings it back by itself (see [At the Cap](#at-the-cap)). `null` turns the cap off. Without it, guessing just under the per-minute limit would never stop. With `Features::devices()` on, browsers the account hasn't signed in from may only make `limits.consecutive_elsewhere` (80) of those failures. The rest are kept for the owner's own browsers, so someone guessing elsewhere can't use the whole cap up, and the two never add up to more than it.

How they count:

- Each attempt is counted before it's verified, so overlapping requests can't all slip under the limit while they're being checked.
- Routes that spend session state (sign in, challenge pages and verifications, enrollment) take Laravel's session lock (`->block()`), so parallel requests in one session can't reuse a WebAuthn challenge or run two verifications of one pending sign in at once. Your cache store must support locks, as the database, Redis, file and array stores do. A sent code doesn't depend on that lock: it's [used up in the cache](#single-use-codes).
- When failures reach an account's limit, that key is locked. Each lock lasts twice as long as the one before (one minute, then two, then four...), up to a day (`limits.longest_lock`). The count of lockouts resets a day after the first one.
- The per-IP limit locks the same way, but never for longer than 15 minutes (`limits.longest_ip_lock`). One person failing behind a shared address (carrier-grade NAT, an office) holds the others up for a quarter of an hour at most, while someone spraying passwords from one address still slows to about `limits.per_ip` guesses every 15 minutes. A browser carrying the account's device cookie isn't held up, and an attempt the address refuses doesn't count against the account. With `Features::devices()` off, everyone on the address waits.
- A success clears the account's per-minute count, and the failures in a row its own kind of browser had made: the owner signing in from a browser they've used doesn't hand whoever is guessing elsewhere their guesses back. On the per-IP count, a success only takes back its own attempt. People signing in from one office address don't use up its limit, and an attacker can't reset either limit by signing in to an account of their own between guesses, even one whose username differs from the victim's by an accent.
- A completed password reset clears the account's failures in a row, per-minute counts, locks and lockout count on the factors that can start a sign in, with those of each of its known devices and of every name they were typed under, so the owner can sign in straight away. A new password chosen by the signed-in user does the same: guesses at the old one say nothing about it. Second factors keep their counts and locks, because a reset only proves control of the mailbox and could otherwise be repeated to keep guessing a code. The `password_reset` log entry records it. Per-IP limits stay, so a reset can't be used to get around them.
- Requests that don't name an account, like usernameless passkey sign ins, only get the per-IP limit, so junk requests can't fill a bucket every user shares.

The per-minute counts, their locks and each typed name's own failures are kept in the cache store Laravel's rate limiter uses (`cache.limiter`, or your default store), with [sent codes and answered WebAuthn challenges](#single-use-codes), and [risk locks](risk.md#actions) in `risk.store`. A count that's gone reads as no attempts, so if the store loses its keys those limits start over and those locks lift: `php artisan cache:clear` and `optimize:clear` empty the default store, and a store that evicts under memory pressure can drop them one at a time. The locks are short, a day at the longest, and what a cleared cache can't reach is what ends the guessing: the failures in a row and the locks that are held are in the `keyring_failure_counts` table. Where the per-minute limits and risk locks have to hold too, point `cache.limiter` and `risk.store` at a persistent store of their own that doesn't evict and that your deploys don't clear. A database or Redis store is the one to use, and Octane's in-memory store is not: see [Octane's Cache Store](#octanes-cache-store).

#### At the Cap

An authenticator that has failed `limits.consecutive` times in a row is disabled for that account, as NIST SP 800-63B-4 asks (Sec. 3.2.2), and stays disabled until it's set up again. What that takes depends on the factor:

- **One that can start a sign in** (the password, a passkey): a completed password reset, a new password chosen while signed in, or `Keyring::unlock($user)`. The sign-in form says to reset the password (`keyring::keyring.locked`), and Keyring dispatches `AccountLocked` and logs `account_locked`. The [`account_locked` notice](security-log-and-emails.md#email-types), which `keyring:install` registers, emails the owner, who may not have been the one guessing.
- **A second factor**: the user signs in another way (another factor, or a recovery code), removes it and adds it again. The challenge page says so (`keyring::keyring.factor_locked`, with a `429`), and each refused attempt dispatches `Lockout` with a `retryAfter` of `null`. A password reset doesn't bring it back, since a reset only proves the mailbox.

From a support tool of your own, `Keyring::unlock($user, 'totp')` clears one factor's failures and locks, whichever kind it is:

```php
use Keyring\Facades\Keyring;

Keyring::unlock($user);            // the password and passkeys, and the risk lock
Keyring::unlock($user, 'totp');    // every authenticator app the user has
```

NIST's rule is that a disabled authenticator is bound again, not switched back on, so `unlock()` goes further than the standard does. Use it once you've checked who you're unlocking it for. For a second factor, nothing else stands between whoever has the password and another round of guesses.

Before the cap, only a success clears the count, and only for its own kind of browser. The rows are never pruned: a row is what keeps an authenticator refused. They go with the authenticator or the user.

**What this costs.** Someone who knows a username can guess at its password from elsewhere until their share is used up: 80 wrong passwords, which takes about 20 minutes at four a minute (slow enough never to meet a lock), or a day and a half for someone who runs into every lock. From then on the password is refused from every browser the account hasn't signed in from, until its owner resets it. The owner's own browsers go on working, because the last 20 failures can only be made from them, and those are theirs alone to use up. That is the price of a disabled authenticator not coming back by itself. With `Features::devices()` off no browser is known, so the whole 100 is anyone's: 25 minutes, and then the password is refused everywhere until it's reset.

A typed username nobody has can't be counted in the database, where there's no account to count it against. So each name's own failures in a row are counted in the cache as well, whoever has the name, for `limits.remember_names_for` (30 days), and that count is the only one the sign-in form answers from. A name with an account, a second name of an account at the cap and a name with none each get a `429` after the same number of their own failures, and the account's count refuses quietly, like a wrong password. A guess costs the database the same statements either way. If the cache loses a name's count, the name goes back to "wrong password" while the account's password stays refused.

#### Locking Until a Reset

By default every lock lifts by itself, the longest after a day, and it takes the cap to stop the guessing. To stop someone who guesses fast sooner, set `limits.lock_after`:

```php
'limits' => [
    'lock_after' => 5,
],
```

An account locked that many times within a day on a factor that can start a sign in is then refused as it would be at the cap, however few failures that took. Locks double, so with the default one-minute window the fifth comes after about a quarter of an hour of steady guessing and at most eleven fit in a day: a higher number never holds anything. The sign-in form says to reset the password (`keyring::keyring.locked`) in place of counting down, and Keyring dispatches `AccountLocked` and logs `account_locked`. The [`account_locked` notice](security-log-and-emails.md#email-types) emails the owner that the account is locked and that resetting the password unlocks it. `keyring:install` registers it; like every security notice, an app that hasn't registered it sends nothing.

The lock ends with a completed password reset, a new password chosen while signed in, or `Keyring::unlock($user)`. It's kept in the database beside the failures in a row, so neither time nor a cleared cache lifts it.

It follows the other limits' rules. Browsers the account has signed in from before are locked and held apart from everyone else, so the owner isn't locked out of a browser they already use. A name nobody has locks the same way and gets the same answer, from the cache, for `limits.remember_names_for`: after that a held name is answered like a wrong password, while the account stays locked. Second factors are never held, because a password reset wouldn't clear them: they keep the cap. That includes security keys, which only ever come second. A name is only told it's held for lockouts made under that name. A hold reached under another name of the same account, or placed by wrong passwords on a confirm page, by a signed-in session, lands on the account's own limit, which the sign-in form refuses quietly: there the right password is answered as wrong, with no hint that a reset would help, so tell the user with the `account_locked` notice, or from `AccountLocked` yourself.

It's off by default: the cap ends the guessing either way, and this only gets someone who guesses fast there sooner, in a quarter of an hour in place of a day and a half.

Factors can set their own limits by overriding `limits()`. A factor that leaves out what the default `limits()` returns leaves out the cap on failures in a row too, so add to the list rather than replacing it. A reset only clears the keys the default `limits()` builds, so a factor with its own per-account keys should clear them in a `PasswordReset` listener. Other routes use Laravel's throttle middleware with the named `keyring` limiter: registration, password reset requests, resets, password changes, email change requests, enrollment confirmations, removing an authenticator, verification emails, and the buttons on the pages emailed links open (confirming or undoing an email change, "this wasn't me", verifying an address) share 6 requests a minute per user, or per IP address for guests. Opening one of those pages is held to 60 a minute per IP address by its own limiter, `keyring-pages`, so a mail scanner that follows the link doesn't use up the six. Usernameless passkey options have a third, `keyring-login-options`, at 60 requests a minute per IP address, because the login page fetches them on every load for autofill. A request any of them refuses is logged as `rate_limited`, once for each wait. Apps can redefine each limiter (see [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits)). Each account can be sent three codes per factor every 10 minutes (`limits.codes` and `limits.codes_per`), however many sign ins, step-ups or enrollments ask for them.

Mail that isn't a guess at anything has a count of its own, since a sign in that succeeds is never counted and the form limiter only counts the sender. An account is sent each kind of [security notice](security-log-and-emails.md#security-emails) five times an hour at most (`limits.notices` and `limits.notices_per`), with every event still in the security log. An account can ask to change its email address that often, and a typed address is mailed about a change that often, whichever accounts ask. An address is mailed by registration that often too (the verification link, another one for an account that never verified, or the notice that someone tried to register with it), however many times the form is sent. No security notice goes to a `MustVerifyEmail` user whose address isn't verified: whoever registered typed it, so it may be anyone's. The notice of a finished password reset is the exception, since the reset link went to that address.

#### Octane's Cache Store

Under Octane on Swoole, Laravel has an `octane` cache store: a Swoole table in the server's memory. It's fast, and it's the wrong place for Keyring's limits. Keep `cache.limiter` and `risk.store` on a database or Redis store. This is what a test run with them on the `octane` store found:

- **Keys hold 63 bytes.** Keyring's fit: everything it counts or remembers there is kept under a short prefix and a hash, whatever the factor is called and however long a username or an ID is.
- **Rows aren't freed when they expire.** A table made for the default 1,000 rows was full after a couple of hundred failed sign ins for made-up names, and from then on every sign in that needed a new row answered `500`. If you use the store at all, size `octane.cache.rows` generously, for everything your app caches there and not only Keyring's keys.
- **Counts aren't atomic across workers.** 48 wrong passwords sent at once against a limit of 5 let 8 through. The database store never let more than 5. What has to happen once (a sent code, an answered WebAuthn challenge, an enrollment's confirmation) relies on the same store taking one write of two.
- **"Forever" is one year, and a restart loses everything.** The marks Keyring keeps for good, such as when an account's limits were last cleared, run out after a year there. Every count, lock, sent code and mark is gone when the server restarts.
- **Laravel's session lock needs another store.** With `CACHE_STORE=octane` as your default store, set `session.block_store` to a store that supports locks. Keyring's sign-in, challenge and enrollment routes take the session lock, and the table has none to give.

The failures in a row and the locks held until a reset are in your database either way, so the cap on guessing holds whatever the cache does. The per-minute limits, sent codes and risk locks are only as good as the store they're in.

### Single-Use Codes

- TOTP codes can't be reused: each authenticator stores the last accepted time step, updated under a database row lock, so two requests with the same code can't both pass.
- A TOTP code is accepted one 30 second step either side of now at most, and only during its own step with a [window of zero](factors.md#authenticator-apps-totp). No wider window can be set.
- Each recovery code works once, used up under the same kind of row lock. Two different codes used at the same time both stay valid until used.
- A set that has had a code used says so until it's replaced (`shouldReplaceRecoveryCodes()`), for your app to send the user to make a new one. Keyring doesn't issue one by itself: see [Known Limitations](#where-keyring-departs-from-a-standard).
- Email codes are random, eight digits (shown as two groups of four, `1234 5678`; spaces are ignored), expire after 10 minutes, allow five wrong guesses per pending attempt, and are replaced by any newer code. A newer code doesn't reset the count, and at the limit the user has to start signing in again. A sent code only verifies the authenticator it was sent to.
- No factor that sends codes, the built-in email codes or [one of your own](factors.md#writing-a-code-factor), can be registered with codes shorter than six digits or that last longer than ten minutes. Keyring throws a `LogicException` instead.
- A sent code works once on every session driver. Its state isn't in the session: the code waiting to be typed (as a keyed hash), the wrong guesses at it and the fact that it was used are kept in the cache store the rate limits use (`cache.limiter`), under the pending sign in, step-up or enrollment it was sent for. A right code is used up the moment it's checked, even when a later step refuses the sign in, and of two requests that send it together one is refused. A newer code ends the one before it, and the guesses stay counted, whichever copy of the session the browser sends. That goes for every code factor, at sign in, step-up and enrollment. If that cache store is cleared, pending codes go with it and the user asks for another.
- An enrollment adds its sign-in method once. That it was confirmed is remembered in the same cache store until it would have expired, so an earlier copy of the session can't confirm it again and bring back recovery codes that have since been replaced or used.
- WebAuthn challenges are random 32 byte values, kept in the session with the sign in, step-up or enrollment they belong to, and used up by the first answer, whether it's right or wrong. The challenge is taken out of the session, and that it was answered is remembered in the cache store the rate limits use (`cache.limiter`) until it would have expired. So a signed answer can't be sent a second time on any session driver: not with an earlier copy of the session that still holds the challenge, which a browser can send back on Laravel's `cookie` driver, and not by two requests that answer one challenge together, of which one is refused. That covers a synced passkey, whose signature counter stays at zero and would let the same answer through twice. It goes for every ceremony: a usernameless sign in, a second factor, a step-up and adding a key. A passkey that verifies on the second-factor step has used its challenge up even when a later check, such as a risk lock, refuses the login. A challenge only completes the ceremony it was issued for: one from the usernameless login options can't finish a second factor or a step-up. Each one runs out on the server too, whatever the browser's timeout: a usernameless one after `webauthn.login_options_for` (5 minutes), a second factor's or a step-up's with its pending login (10 minutes), and a new key's with its enrollment (15 minutes).
- A passkey's signature counter is checked and saved under the same kind of row lock, so two assertions can't both pass against one stored count, and a slower request can't lower it.

### Second Factors and Step-Up

- Policies count distinct categories, so two factors of the same kind are never treated as multi-factor. AAL2 further needs one of the two to be something the user has (NIST SP 800-63B-4, Sec. 2.2.1): a password beside a factor that is only a biometric is an AAL1 session.
- Assurance levels follow NIST SP 800-63B-4 as far as a library can check. A passkey that syncs reaches AAL2. AAL3 needs a phishing-resistant key that reports on every sign in that it can't leave its device, that was added with a verified attestation, and that either verified the user itself or was used with a password: another built-in authenticator's user verification is never counted beside it. A factor of your own that reports only inherence does count beside an attested key, as NIST's "or a biometric comparison" allows (Sec. 2.3.1). A key nothing vouches for stays at AAL2, though a policy or route can still ask for one with `deviceBound()`.
- NIST AAL3 further needs authenticators and verifier cryptography validated to FIPS 140. Keyring can't supply or check either, so a session it calls AAL3 has met NIST's rules for the authentication and nothing more.
- Email codes are opt-in (`EmailCode::asExtraStep()`), since NIST doesn't accept email as an authenticator and the inbox can also reset the password. A code is a step at sign in and never a factor: a password and an emailed code is an AAL1 session, doesn't pass `keyring:aal2` or `keyring.enrolled`, doesn't earn a trusted device, and can't stand in for a possession factor the account has.
- A passkey or security key only counts as inherence when it actually verified the user that time.
- The first recovery codes are shown to a session that has proved two factors: confirming a new sign-in method takes proving it, and the session counts that proof from the same response (NIST SP 800-63B-4, Sec. 3.1.2.1). Later sets need a fresh verification of both.
- With `noDowngrade()`, users with a passkey or security key can't be offered a weaker way in. Recovery codes stay on offer as the way back in, unless you pass `except: []`.
- With `ifEnrolled()`, a policy the user can't fully meet still asks for the strongest version they can give, so a user with a second factor never signs in with one factor.
- Adding, removing or changing sign-in methods, revoking devices, changing the password and starting an email change need a fresh verification with the strongest combination the account can give, and at least what signing in would ask (NIST SP 800-63B-4's rule for binding authenticators, Sec. 4.1.2.1). Users with a possession factor always use one, and users with a key that can't leave its device use that, so a stolen session plus a phished password and code isn't enough. A recovery code with the password stands in for a lost key, as NIST's account recovery allows. At a step-up a recovery code never counts on its own, so an account with nothing but a set of codes beside its password confirms with the password.
- The fresh window is fixed from the moment of verification and doesn't slide with activity.
- Users can't add a sign-in method until their email is verified (with `MustVerifyEmail`), so someone who registers an address first can't plant a factor that survives the real owner's password reset. With registration on, a user model that can't verify its email can't add sign-in methods at all.
- Users can't remove authenticators below what they need to sign in, even with several removals at once.

### Sessions and Devices

- Every signed-in Keyring route checks Keyring's guard (`auth:{guard}`), and the step-up middleware reads the user from it, so another guard's user can't stand in.
- Every signed-in session is in Keyring's registry and is checked on every `web` request (and any other group you add `keyring.session` to), so revoking one takes effect on its next request with any session driver. Timeouts and revocations only reach routes that run that middleware, and the [conformance suite](testing.md#the-conformance-suite) fails for a signed-in route that doesn't.
- An account can have 100 sessions at once (`sessions.max`). A sign in beyond that ends the session unused longest and is never refused, so holding an account's sessions can't keep its owner out. See [How Many Sessions](devices-and-sessions.md#how-many-sessions).
- A session ends after two hours unused (`sessions.idle`) and 30 days after sign in (`sessions.absolute`), counted on its registry record, so neither depends on your session driver or `session.lifetime`. Each assurance level lapses on NIST SP 800-63B-4's clock (AAL2: 1 hour idle or 24 hours; AAL3: 15 minutes or 12 hours) until the user verifies again. A session past its level's limits is treated as the lower level and stays signed in, which is Keyring's reading of Sec. 5.1 and departs from Sec. 5.2. With `sessions.end_on_lapse` it ends instead when the level it signed in at runs out, as Sec. 5.2 words it, and "remember me" brings nothing back.
- A browser that ticked "remember me" is the one exception to the two hours, on purpose: it may stay away for 14 days (`sessions.remember_idle`) and be signed back in, inside the same 30 days. After two hours unused it holds no level, so anything behind `keyring:aal2` or `keyring.fresh` asks it to verify again. See [Inactivity and "Remember Me"](devices-and-sessions.md#inactivity-and-remember-me).
- "Remember me" can't outlast the session it was ticked for. Laravel's cookie alone signs nobody in: the browser also holds a Keyring cookie naming that session's registry record, and coming back carries the session on with the limits it started with and nothing proved. Once the record has timed out, been revoked or been ended by a risk response, both cookies are refused, even from a client that kept them after being told to delete them.
- A "remember me" cookie works once. Coming back moves the session to a new record and gives the browser a new cookie, so a copy of the pair brings back nothing the browser it was taken from hasn't already had. If a used cookie is sent again, or a browser is still signed in on the record it named, two browsers held the same pair: the session ends for both, with a `RememberMeReused` event and a `remember_me_reused` log entry. The one exception is the same browser's other requests in the few seconds after (`sessions.remember_grace`), which join the session the first one resumed. They can't start another, and sending the cookie again doesn't make those seconds any longer.
- A resumed session's device, IP address and browser are those of the request that resumed it, on a record of its own. A browser still on the record from before is never compared with them.
- A user can always see their sessions and end any one of them or all the others (`/user/sessions`), whatever features are on. Ending needs a fresh verification, looking doesn't. Only their own can be found.
- A session's registry ID, which its "remember me" cookie carries, is never sent to a page. The sessions list names each one by a keyed hash of it, which can't be turned back into the ID or used as a cookie.
- A session whose registry record has gone missing is signed out rather than started over.
- An administrator can end one user's sessions, or everyone's, with `php artisan keyring:sign-out`. "Remember me" brings none of them back. See [For Administrators](devices-and-sessions.md#for-administrators).
- An account your app stops letting sign in ([`allowSignInWhen()`](sign-in-flow.md#who-may-sign-in)) is refused wherever a session starts or carries on, and the first request that's refused ends every session the account has, with its "remember me" cookies and trusted devices. Until one of its sessions makes a request they're still on record, so call `Sessions::signOutEverywhere()` as you set your flag to end them there and then.
- Signing a user out everywhere and a session moving to a new record take turns, so a "remember me" cookie coming back at that moment can't carry a session past the sign-out.
- A revocation can't be undone by a request saving a stale copy of its session.
- Laravel's session ID is never stored by Keyring or written to the security log.
- Devices are recognised by a random, httpOnly cookie, stored as a hash. A device is never a factor, only an input to your policy and risk signals.
- Keyring's two cookies (the device cookie and the "remember me" one) are httpOnly and `SameSite=Lax`. Once the app is served over HTTPS (`APP_URL` is `https`, or `session.secure` is on) they are always `Secure` and carry the `__Host-` prefix, or `__Secure-` when your cookies are shared with subdomains. See [Keyring's Cookies](devices-and-sessions.md#keyrings-cookies).
- Signing out everywhere also stops trusting the other devices and cancels pending email changes, so whoever had the account can't skip the second factor on a device they trusted or finish a change they started.
- A device is only trusted after a login that reached AAL2, never after the password alone or with an emailed code. An account's device never takes a cookie value the browser sent: the first sign in from a browser, a login that reaches AAL2 and any grant of trust each give it a new one. So being recognised, like being trusted, can't rest on a cookie placed in the browser before the user signed in, and whoever placed it isn't recognised as the account's browser from their own.
- Every device stops being trusted when the password changes, an authenticator is removed, an email change is applied or a signed-in request places a risk lock. A lock placed by a login attempt doesn't, as above.

### Account Changes

- With `Features::updatePasswords()` and `Features::emailChanges()` on, `password` and `email` can only change through Keyring's flows. Bypassing that needs `Keyring::withoutProtection()`, which is announced and logged. Without them, your app changes those attributes itself.
- An email change needs a fresh verification, confirmation from the new address, and confirmation from the current address unless the session proved a second factor the account has had for a week (`email_changes.established_after`) and since before it signed in. A recovery code isn't one.
- An email change never reveals whether the new address has an account, in its answer, its timing or the pending change it shows: its emails, like the reset email, are sent after the response.
- An email change only applies if the address is still the one it was requested from.
- Emailed links (email verification, email change confirm and revert, and "this wasn't me") only act on a button press (a POST), so mail scanners that open links change nothing. No `GET` route of Keyring's changes state. The page posts the link's token or signature in the body to a URL without it, as the password reset does, so the request that acts doesn't leave it in access logs a second time.
- A password reset with a bad token gets the same answer for every address. Password rules, which are shorter for accounts with MFA, only run once the token checks out.
- Reverting an email change signs out every session, ends any sign in still waiting for its second factor, closes later changes and removes sign-in methods that weren't established when it was asked for, with the recovery codes when none of what's left is a factor for them to recover. Cancelling a change doesn't stop its revert link working.
- While an email change can be reverted, nobody else can take the address it replaced, so the revert always has somewhere to put it back.
- Password resets give the same answer for every address, sign out every session, cancel pending email changes, and lift risk locks and sign-in lockouts.
- A password change takes the current password as well as a fresh verification, checked by Keyring itself rather than by your action. A user with no password yet sets one with the fresh verification alone.
- Password changes cancel pending email changes, so someone who knew the old password can't finish one.
- Every change to how someone signs in can end their other sessions. A password reset and a reverted email change end every session. A password change and an applied email change end the others unless told not to (`sign_out_others` on the request, `email_changes.sign_out_others` in the config). Adding or removing an authenticator, or making new recovery codes, ends them when the request asks (`sign_out_others`). And "sign out everywhere else" (`DELETE /user/sessions`) is always registered, whatever features are on.
- New passwords need at least 8 characters with a second factor and 15 without, and neither minimum can be configured below 8. Any characters are accepted, with no composition rules.
- New passwords are checked against the 10,000 most common of 8 characters or more and the 3,000 most common of 15 or more, in every environment, and against your app's name, the words you list in `passwords.context` and the user's own name and email address, with look-alike characters read as letters. The whole password is compared, as NIST SP 800-63B-4 Sec. 3.1.1.2 requires: one made up of those words is refused, and a passphrase that only has one in it is not.
- In production, new passwords are also checked against breach lists (Have I Been Pwned). That check lets a password through when the service can't be reached, unless you set `passwords.refuse_unchecked`.
- New passwords are refused rather than silently cut short by bcrypt. With bcrypt that limit is 72 bytes, so hash with argon2id to accept every password up to `passwords.max`.
- Passwords never expire. A user is held until they choose a new one when there's evidence theirs is compromised (NIST SP 800-63B-4, Sec. 3.1.1.2): by your app, by a risk response of yours, or by Keyring's own response when the `BreachedPassword` signal, which is off until you turn it on, finds the password they just signed in with in a breach. The hold outlasts signing out and clearing the cache, ends with a password change or reset, and is never placed on an account without a password.

### Links and Headers

- Every Keyring response is sent with `Cache-Control: no-store, private` and `X-Content-Type-Options: nosniff`, and signing out sends `Clear-Site-Data`. The referrer policy and the frame header are below.
- Every emailed link (password reset, email change, email verification, "this wasn't me") is built from `APP_URL`, never from the request that caused the email: not its `Host` header, and not an `X-Forwarded-Prefix` your proxy passed on.
- Signed links are signed over the path and query only, and checked with `keyring.signed:relative` (Laravel's `signed` middleware, with refused links logged), so a forged `Host` header can't redirect them.
- Pages opened from emailed links (password resets, email verification, email changes, "this wasn't me") have the link's token or signature in their URL, so they're sent with `Referrer-Policy: no-referrer`: nothing the page loads is told its URL, your own assets and analytics included. A failed form still finds its way back, because Keyring notes the page in the session.
- Every other Keyring response sends `Referrer-Policy: same-origin`, so other sites never see its URL and your own app still does.
- A site that opens one of Keyring's pages in a new window keeps no handle on it: each response is sent with `Cross-Origin-Opener-Policy: same-origin-allow-popups`, unless it already has that header. A window the page opens itself, for a social login say, still answers to it.
- No Keyring response may be shown in a frame: each is sent with `X-Frame-Options: DENY`. That covers the pages that act on one press of a button (confirming an email change, undoing one, reporting a device, verifying an address) and the sign-in, challenge and confirm pages, which are what a page on another site would load invisibly and line its own button up over. A response that already says who may frame it is left as it is: one with an `X-Frame-Options` of its own, or a `Content-Security-Policy` with a `frame-ancestors` directive. See [A Content Security Policy](#a-content-security-policy).
- An Inertia app keeps the policy of the page it first loaded. So when the form on an emailed link's page succeeds, Keyring answers Inertia with a full page visit (`409` with `X-Inertia-Location`), and the next page comes with its own policy. Otherwise every page after it would send no `Referer` either, signed in or not.

#### Emailed Links

An app on several domains can start the links somewhere other than `APP_URL`, such as the tenant the user belongs to:

```php
Keyring::linkRootUsing(fn () => tenant()->url);
```

Work it out from something the server knows. The request's `Host` header is whatever the sender says, and a link built from it sends a real reset token to their site. The signature covers the path and query, so links keep working under any root.

#### Tokens in Emailed Links

An emailed link has to carry what makes it work, so its token or signature is in the URL of the page it opens. OWASP ASVS 5.0.0 (14.2.1) wants nothing sensitive in a URL, and for these links Keyring can't meet that. What it does is above: the page changes nothing and posts the token in the body of the request that acts, it's sent with `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, and none of the links lasts long. A reset link stops working once it's used, or after `auth.passwords.*.expire` (60 minutes in a new app). An email change's confirming links last 24 hours (`email_changes.confirmable_for`) and its undo link a week (`revertable_for`), and each works once. A verification link lasts `auth.verification.expire` (60 minutes).

The reset link also carries the account's email address, as Laravel's own does, and it stays. Laravel's broker finds a reset by its address: its table is keyed by the address and holds the token as a password hash, which can't be looked up. So the form has to post the address, and a link without it leaves the user to type it into a field that most reset pages, Laravel's starter kits' among them, show filled in and read-only. The address is also less than the token: it's who the email was sent to. To keep it out of the URL all the same, build the link yourself and have your page ask for the address. Keyring leaves a callback of yours alone:

```php
use Illuminate\Auth\Notifications\ResetPassword;
use Keyring\Support\Url;

ResetPassword::createUrlUsing(fn (User $user, string $token) => Url::route('password.reset', ['token' => $token]));
```

`Url::route()` builds from `APP_URL`, as Keyring's own link does. The `reset-password` page then gets an empty `email`.

### Request Input

A URL ends up in places a request's body doesn't: access logs, proxies, the browser's history. Laravel's `$request->input()` reads the query string as well as the body, so a password sent as `POST /login?password=...` would work, and be logged.

- Keyring reads what proves something from the body alone, as a form or as JSON: passwords (signing in, confirming, changing, resetting, registering, removing the last second factor), codes, WebAuthn credentials, the reset token, and the tokens and signatures the pages of [emailed links](#links-and-headers) post.
- Sign in, challenges, step-up, enrollment and password resets validate against the body, so a required field that's only in the query string fails as missing. That covers a factor of your own: its `rules()` are checked the same way.
- Your `CreatesNewUsers`, `ResetsUserPasswords` and `UpdatesUserPasswords` actions are passed the body, not the query string.
- A `GET` has no body, so a sign in you start from a `GET` route with `Keyring::attempt()`, like a social login's callback, is read from its query string.
- Fields that prove nothing can still come from either: `remember`, `trust`, which authenticator to show, `sign_out_others`, and the new address of an email change.

### Storage

- TOTP secrets are encrypted with `APP_KEY`. [Cryptography](#cryptography) lists every algorithm and key.
- Recovery codes and email codes are stored as keyed hashes (HMAC-SHA-256). A recovery code is only stored with 112 random bits or more: Keyring's own have 128, those imported from Fortify 119, and no other form is stored or accepted. A sent code is far shorter, so its hash is kept in your cache for ten minutes at most and allowed five guesses.
- Keyed hashes never use `APP_KEY` itself. Each kind (recovery codes, one-time codes, reserved addresses, WebAuthn user handles, session handles) has a key of its own, derived from `APP_KEY` with HKDF, so a hash made for one can't pass as another and none is made with the key Laravel encrypts and signs with.
- Email change tokens are stored as SHA-256 hashes, and the addresses in a pending change are encrypted.
- Device tokens are stored as SHA-256 hashes.
- A session's registry ID is stored as it is: see [Algorithms](#algorithms) for why one read from the database signs nobody in.
- WebAuthn credential IDs longer than 512 characters are refused rather than cut short.
- WebAuthn user handles are an HMAC of the user's model and ID, never the ID or email, so two user models with the same ID don't share one.

### Logging

- Sign ins, failed factors, lockouts, session starts and ends, sessions "remember me" carried on, and every change to how an account signs in are recorded as shipped. A session your own code starts with `Auth::login()` isn't. They go in the [security log](security-log-and-emails.md) table, which is on by default, or in your app's log when you turn the table off. There is no setting that records nothing.
- What was refused is recorded too: a request for someone else's authenticator, device or verification link, a sign-in method that wasn't added, a removal that would have left the account unable to sign in, an emailed link with a wrong, ended or expired token or signature, a request the form rate limiter turned away, and a verification the pipeline's final gate turned away. None of it changes the answer the requester gets.
- No entry holds a password, code, token, signature, session ID or request body, in the table or in the app's log. Form validation errors aren't logged.
- Every entry carries a severity, the ID of the request that wrote it and the time. In the table the time is in your `app.timezone`, which is UTC unless you changed it; in your app's log it's written with its offset. See [Times](security-log-and-emails.md#times).
- A refused request can't fill the log. A lock is logged once when it starts, not for each request it refuses, and refusals are capped per account or IP address, with one entry to say where the log stopped. See [Refusals That Repeat](security-log-and-emails.md#refusals-that-repeat).
- A log write that fails never fails the sign in, with one exception: `Keyring::withoutProtection()` doesn't run unless its entry was written.
- Old entries, devices, ended email changes and ended sessions are deleted every day by a task Keyring schedules itself, and a force deleted user's records are deleted with them.

## What Keyring Keeps

Everything Keyring stores about a person, how it's protected, how long it stays and who can read it. Built from the migrations, so a table you've added columns to holds whatever you put there as well.

| Where | Personal data | Protected by | Kept for |
|---|---|---|---|
| `keyring_authenticators` | The name the user gave it (plain). TOTP secrets and recovery codes in `secret`. A passkey's or security key's credential ID, public key, AAGUID and transports. The address an email code goes to, when a factor keeps one. | `secret` is encrypted with `APP_KEY`, and recovery codes are keyed hashes inside it. Credential IDs and public keys are plain: they're public by design, and useless without the key itself. `secret`, `public_key` and `credential_id` are hidden when the model is serialised. | Until the user removes it, an email change is undone, or the user is force deleted. |
| `keyring_devices` (with `Features::devices()`) | IP address, user agent, a name, and the [location](devices-and-sessions.md#locations) your locator returned (country, region, city, coordinates). | The device cookie's token is a SHA-256 hash, hidden when serialised. The rest is plain. | 30 days after it's signed out (`devices.keep_revoked_for`), a year after it was last seen (`devices.keep_unseen_for`), or until it's the oldest past `devices.limit`. Deleted with a force deleted user. |
| `keyring_sessions`, or your cache with the `cache` driver | The user's ID, IP address, user agent, whether "remember me" was ticked, and when they signed in and were last active. | The ID is Keyring's own random one, never Laravel's session ID. The rest is plain. | Until the session expires or is revoked, then the next daily prune. A record "remember me" replaced stays until it would have expired. Cache records expire on their own. |
| `keyring_pending_changes` (with `Features::emailChanges()`) | The new and the old email address. | Both addresses are encrypted with `APP_KEY`, with a keyed hash of the old one to find it by. The three tokens are SHA-256 hashes. All of them are hidden when serialised. | 30 days after the change ended (`email_changes.keep_ended_for`). Deleted with a force deleted user. |
| `keyring_events` (with `Features::securityLog()`) | IP address, user agent, the device's ID, and in `meta` an authenticator's name or a device's description. | Plain. Never a password, code, token, signature, session ID or request body. | 180 days (`security_log.keep_for`). Deleted with a force deleted user. |
| `keyring_failure_counts` | None beyond whose it is: the user's ID, the factor, the authenticator's ID and two counts of failures in a row. | Plain. | Until a success, a password reset or `Keyring::unlock()` clears it, or its authenticator is removed. Never pruned, since a row is what keeps an authenticator refused [at the cap](#at-the-cap). Deleted with a force deleted user. |
| `keyring_password_holds` | That the user has to choose a new password, and the reason your app or a risk response gave: write nothing personal there. | Plain. | Until the password changes or the hold is called off. Deleted with a force deleted user. |
| Your app's log (without `Features::securityLog()`) | The same as `keyring_events`, one line per event. | Whatever protects that log channel. | Whatever that channel keeps (`days` on a `daily` channel). |
| The session | A sign in waiting for its second factor, an enrollment in progress (including the secret being set up), and what the session has verified. | Encrypted with `APP_KEY` inside the session, whichever session driver holds it. | 10 minutes for a pending login (`pending_logins.keep_for`), 15 for an enrollment (`enrollments.keep_for`), otherwise the session's life. |
| The rate limiter's cache store | Counts of attempts, keyed by a SHA-1 of the factor with the account, the typed username or the IP address. Also hashes of sent codes, marks for answered WebAuthn challenges and enrollments under way, and risk locks (in `risk.store`), which are kept under the user's ID. | Hashed keys, so the store holds no names or addresses to read back. A risk lock's key holds the user's ID as it is. | A minute for counts, up to 24 hours for locks, 30 days for the failures in a row counted under a typed username (`limits.remember_names_for`). |
| Laravel's own tables | The reset token and address in `password_reset_tokens`, and `remember_token` on your users table. | Laravel hashes the reset token. | Laravel's `auth.passwords.*.expire`. Keyring deletes a user's reset tokens when they're deleted or their address changes. |

To store less of an address, or none, see [What's Stored](security-log-and-emails.md#whats-stored): `Keyring::recordIpsUsing()` applies to devices, sessions and the log alike. Security emails pass the IP address and a description of the browser to the user they're about.

**Who can read it.** Keyring has no admin screens and no route that returns another person's records. A signed-in user can read their own: [`GET /user/devices`](devices-and-sessions.md#listing-and-revoking-devices) lists their devices with IP address and location, ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts) show them the type, time and IP address of entries about their account, and [`Keyring::activity($user)`](security-log-and-emails.md#showing-recent-activity) returns their entries if you build a page for it. Everything else is reached only by your own code and by whoever can read your database, cache and logs, so those are what to restrict: treat `keyring_events` and the log channel as you would any audit log.

**Deleting someone.** Force deleting a user deletes their authenticators, devices, pending changes, security log entries and reset tokens, and revokes their sessions, which the next prune removes. A soft deleted user keeps all of it in case they're restored, until each record's own time is up.

## What Your App Must Provide

Keyring sets the headers and cookies of its own responses. The rest of what a browser needs belongs to your app and your server, because it covers every response, not only Keyring's. This is what Keyring expects to be there, what it does about each, and what happens without it.

| Your app provides | Keyring does | Keyring doesn't |
|---|---|---|
| HTTPS on every request, and HSTS | Builds emailed links from `APP_URL`, and keeps its own cookies to HTTPS once `APP_URL` is `https` | Redirect HTTP to HTTPS, or send `Strict-Transport-Security` |
| Trusted proxies, behind a load balancer | Reads the client's address and scheme from the request Laravel gives it | Work out which proxies to trust |
| `SESSION_SECURE_COOKIE=true` | Makes its own two cookies `Secure` and gives them the `__Host-` prefix | Change the flags or name of Laravel's session, CSRF or "remember me" cookies |
| A `Content-Security-Policy`, with `frame-ancestors` | Sends `X-Frame-Options: DENY` on its own responses, unless yours already say who may frame them | Send a policy: your layout and assets decide what one has to allow. Stop your other pages being framed |
| `X-Content-Type-Options: nosniff` on your own responses | Sends it, with `Cache-Control: no-store`, `X-Frame-Options: DENY`, a `Referrer-Policy` and a `Cross-Origin-Opener-Policy`, on every Keyring response | Add headers to routes that aren't Keyring's |
| A bot check, if your forms need one | Limits how often anything can be tried, and makes every refusal take as long as the next | Tell a person from a script: no CAPTCHA, no challenge, no minimum time to fill in a form |

### HTTPS and HSTS

Serve the whole app over HTTPS, redirect plain HTTP to it, and send `Strict-Transport-Security` so a browser that has been once never tries HTTP again. That's your web server's or load balancer's job, for every response.

Set `APP_URL` to the `https://` address. Keyring takes that as the sign the app is served over HTTPS: it's where emailed links start, the origin passkeys are bound to, and what decides whether [Keyring's cookies](devices-and-sessions.md#keyrings-cookies) are `Secure` and prefixed.

Without HTTPS, passwords, codes and session cookies cross the network in the clear, and browsers refuse passkeys and security keys altogether except on `localhost`. Keyring still works over plain HTTP for local development, with unprefixed cookies that aren't forced `Secure`.

### Trusted Proxies

Behind a load balancer or CDN that ends TLS, tell Laravel which proxies to trust (`trustProxies()` in `bootstrap/app.php`). Until you do, every request looks like plain HTTP from the proxy's address. Then:

- every user shares one address for the [per-IP rate limit](#rate-limiting), so one person's failures hold everyone up,
- the IP addresses in the security log and on the devices page are the proxy's,
- Laravel only marks its own cookies `Secure` on a request it knows came over HTTPS, so with `SESSION_SECURE_COOKIE` unset they're sent without it.

Keyring's own cookies don't depend on this, since they go by `APP_URL`. Only trust proxies you run: a trusted proxy's `X-Forwarded-For` is believed, and a client that can reach the app directly could then choose its own address. `X-Forwarded-Prefix` and the `Host` header never reach an [emailed link](#links-and-headers) either way.

### Secure Cookies

Set `SESSION_SECURE_COOKIE=true` in production. Laravel then marks its session cookie, its CSRF cookie and its "remember me" cookie `Secure` on every response, whatever the request looked like. Keyring reads the same setting, as well as `APP_URL`, to decide about its own.

Keyring's two cookies need nothing from you: over HTTPS they're `Secure`, httpOnly, `SameSite=Lax` and named `__Host-known_device` and `__Host-remembered_session`, or `__Secure-` when `SESSION_DOMAIN` shares your cookies with subdomains. See [Keyring's Cookies](devices-and-sessions.md#keyrings-cookies). If you set your own names (`devices.cookie`, `sessions.remember_cookie`), they're used exactly as written and the prefix is yours to add.

The session cookie is Laravel's, and its name is yours. Give it the prefix as well:

```ini
SESSION_SECURE_COOKIE=true
SESSION_COOKIE=__Host-session
```

A `__Host-` cookie needs `SESSION_PATH=/` and no `SESSION_DOMAIN`, which are Laravel's defaults. With a `SESSION_DOMAIN`, use `__Secure-`. Laravel names its "remember me" cookie itself (`remember_web_...`), so that one can't be prefixed. It signs nobody in without Keyring's cookie beside it: see ["Remember Me"](devices-and-sessions.md#remember-me).

Keep `SESSION_SAME_SITE` at `lax` or `strict`, and leave `SESSION_HTTP_ONLY` on. Keyring's routes use the `web` middleware group, so Laravel's CSRF check covers every one that changes anything. Don't except Keyring's paths from it, and keep it in the list if you replace `keyring.middleware`.

### A Content Security Policy

Keyring renders its pages through your app, as Inertia components or Blade views in your own layout. Which scripts, styles and fonts a policy has to allow depends on that layout, so Keyring sends no `Content-Security-Policy`, and your app must.

Whatever else yours says, include `frame-ancestors`:

```
Content-Security-Policy: frame-ancestors 'none'
```

Use `'self'` if your app frames its own pages. Without it another site can load a page in an invisible frame and line a button of its own up over yours. The CSRF token doesn't help there, because the press really does come from your page. `SameSite=Lax` cookies aren't sent to a framed page on another site, which stops the signed-in cases in current browsers, but a page that works signed out is still exposed.

Keyring's own pages are covered without it. Every Keyring response is sent with `X-Frame-Options: DENY`, which is where it matters most:

- the login, challenge and confirm pages, where someone types a password or a code,
- the pages emailed links open (`reset-password`, `email-verification`, `email-change`, `device-report`). Three of those do their work with one press of a button, and they work signed out.

That header is Keyring's default, and your policy can take its place. When a Keyring response already carries a `Content-Security-Policy` with `frame-ancestors`, or an `X-Frame-Options` of its own, Keyring adds nothing: your app has decided. Keyring's middleware sees the headers set by whatever runs inside it, which is the route itself and any middleware listed after it in `keyring.middleware`. A policy added further out (your `web` group, a global middleware or your web server) arrives after Keyring has added `DENY`, and browsers then go by `frame-ancestors` and ignore `X-Frame-Options`, so a policy of `'self'` still lets your app frame those pages. Two different `X-Frame-Options` headers on one response are read as `DENY`, so if your web server sends `SAMEORIGIN` everywhere and you do want to frame Keyring's pages, send it from inside as well, or say so with `frame-ancestors`.

Your other pages get nothing from Keyring, so send the policy on every HTML response, with `X-Frame-Options: DENY` (or `SAMEORIGIN`) beside it for older browsers.

### Headers on Your Other Responses

Keyring's middleware (`Keyring\Http\Middleware\AddSecurityHeaders`) is on Keyring's routes only. Send `X-Content-Type-Options: nosniff` on the rest of your app too, so a browser never treats a response as a type it doesn't say it is, and decide your own `Referrer-Policy` and `Cache-Control` for pages that show account details. A small middleware on your `web` and `api` groups, or your web server's config, covers all of it.

If you take Keyring's middleware out of `keyring.middleware`, its responses lose `no-store`, `nosniff`, `X-Frame-Options`, their opener policy and their referrer policy unless yours send them. The pages emailed links open have a token in their URL, so they need `Referrer-Policy: no-referrer`.

### Bot Checks

Keyring slows guessing down with [rate limits](#rate-limiting) and doesn't try to tell a person from a script. It has no CAPTCHA, no challenge and no minimum time between showing a form and taking its answer. OWASP ASVS 5.0.0 asks for realistic human timing at Level 3 (2.4.2), and OWASP's Authentication Cheat Sheet suggests a CAPTCHA after failed attempts. Which service to use, when to show it and what to do for the people it gets wrong are your app's decisions, so the check is yours to add.

For signing in, it's a [pipeline step](sign-in-flow.md#writing-a-step) of your own, put before the limits so a request that fails it is never counted as an attempt on anyone's account:

```php
namespace App\Keyring;

use Closure;
use Illuminate\Validation\ValidationException;
use Keyring\Pipeline\Context;

class CheckForBots
{
    public function __construct(
        protected BotCheck $bots,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        // Where a sign in starts. A challenge page only comes after a right password.
        if ($context->identifying && ! $this->bots->passes($context->request)) {
            throw ValidationException::withMessages(['captcha' => __('Please confirm you are not a robot.')]);
        }

        return $next($context);
    }
}
```

```php
// app/Providers/KeyringServiceProvider.php
use Keyring\Pipeline\Steps;
use Keyring\Pipeline\Steps\EnsureNotThrottled;

Keyring::pipeline(fn (Steps $steps) => $steps->before(EnsureNotThrottled::class, CheckForBots::class));
```

`BotCheck` stands for whatever you use: a CAPTCHA's server-side verification, or a signed timestamp from your form that says how long ago it was shown. The step runs inside the timebox, so a refusal takes as long as any other.

Registration, password reset requests and the other forms don't go through the pipeline. For those, add a middleware of your own to [`keyring.middleware`](configuration.md#routes) that checks the routes you name (`register.store`, `password.email`).

## Cryptography

Everything Keyring does with a key or an algorithm, and where. It adds no cipher or hash of its own: each one below is PHP's, Laravel's or a library's.

### Keys

| Key | Where it lives | Used for |
|---|---|---|
| `APP_KEY`, and `APP_PREVIOUS_KEYS` for what was made before a rotation | Your environment | Laravel's encrypter and signed URLs, directly. Keyring never uses it as a key of its own. |
| Five purpose keys, one each for recovery codes, one-time codes, reserved addresses, WebAuthn user handles and the handles a page knows sessions by | Nowhere: derived on each use from `APP_KEY` (and each previous key) with HKDF-SHA-256, the purpose's name as the label | Keyring's keyed hashes. A hash made for one purpose can't pass as another, and none is made with the key that encrypts. |
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
| HMAC-SHA-256 under a purpose key | Recovery codes; emailed codes, and those of your own code factors, while they wait in the cache to be typed; the lookup hash of an address an email change holds; the WebAuthn user handle; the handle a page knows a session by | Values that are only ever compared or looked up, never read back. |
| SHA-256, unkeyed | Device tokens and email change tokens (confirm, current address, revert) | Long random tokens, so a copy of the table can't be used as one. Each has well over 128 bits, which is why a plain hash is enough. |
| SHA-256, unkeyed | The mark a pending login keeps of the user's password hash and address, inside the encrypted session | Noticing that either changed. Not a secret. |
| None: stored as it is | A session's registry ID, in `keyring_sessions` or the cache | Nothing, on purpose. The ID isn't a credential by itself. It only does anything from inside a Laravel session, which is kept on the server or, with the `cookie` driver, in a cookie encrypted with `APP_KEY`, or from inside the "remember me" cookie, which is encrypted the same way and only works beside Laravel's own. Someone who can read the table can make none of those without the key. Laravel keeps its own session IDs and `remember_token` the same way. |
| HMAC-SHA-1, or HMAC-SHA-256 or HMAC-SHA-512 where the factor is [set up with one](factors.md#authenticator-apps-totp) | TOTP codes (RFC 6238), six digits every 30 seconds | A legacy algorithm in OWASP ASVS 5.0.0's Appendix C (requirement 11.4.1), kept as the default because it's the one every authenticator app makes, and several ignore a request for another. |
| Laravel's hash manager, with your `hashing.driver`: bcrypt by default, or Argon2id | Passwords, the hash an unknown account spends, and the reset tokens Laravel's broker stores | Keyring calls `Hash` and never picks the algorithm or its cost. |
| ECDSA with P-256 and SHA-256 (ES256), Ed25519 (EdDSA), and RSASSA-PKCS1-v1_5 with SHA-256 (RS256, off by default, 2048 bits at least) | Signatures from passkeys and security keys, limited to [`webauthn.algorithms`](passkeys.md#signature-algorithms) | Proof of holding the key. SHA-256 also hashes the client data and the relying party ID, as WebAuthn defines. |
| X.509 path validation: ECDSA, Ed25519, Ed448 or RSASSA-PKCS1-v1_5 signatures over SHA-224 or longer, RSA keys of 2048 bits at least, never SHA-1 | Attestation chains, only for a factor with [`requireAttestation()`](passkeys.md#requiring-attestation) | Which maker's key this is. The algorithms are whatever the maker signed its certificates with, so this accepts RSA with PKCS #1 v1.5 padding, which ASVS doesn't approve: several makers' roots use it (requirement 11.6.1). Off by default. |
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
| WebAuthn user handles | HMAC-SHA-256 of the user's model and ID under a purpose key, not random | 256 bits, and not guessable without `APP_KEY` |
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
| The keyed hash (HMAC-SHA-256) or how its keys are derived | Fixed in code | A new release would have to re-make them: reserved address hashes can be recomputed from the encrypted address, recovery codes can't be (only the hash is kept) and would be issued again, and a WebAuthn user handle stays for as long as the user has a key that knows it. |
| The token hash (SHA-256) | Fixed in code | Tokens can't be rehashed, since only the hash is kept. Device cookies and pending email change links would be issued again. |

Those last two are where Keyring stops short of OWASP ASVS 5.0.0's requirement 11.2.2, that any algorithm can be swapped. Its stored hashes carry no tag saying which scheme made them, so a release that changed one couldn't take the old and the new side by side: it would have to re-make what can be re-made and issue the rest again, as the table says. A tag is only worth having on the day of such a change, and neither algorithm has a weakness to move away from, so Keyring doesn't carry one yet.

### Peppering Passwords

NIST SP 800-63B-4 recommends (Sec. 3.1.1.2), beyond the salted hash, a keyed hash or encryption of it under a secret kept apart from the database, often called a pepper. OWASP's Password Storage Cheat Sheet suggests the same. Keyring doesn't build one in, for three reasons. The password hash is your `users.password` column and Laravel's hasher, shared with everything else in your app that checks a password, so a pepper only Keyring knew about would break those. A pepper is only worth having when its key lives somewhere the database's attacker can't reach, and where that is (an HSM, a secrets manager, at least a separate environment variable) is your infrastructure's decision. And losing or rotating it locks out every user at once, so it needs a plan that belongs to whoever runs the app.

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
| One password hash (bcrypt or Argon2id, at your cost setting) | Every password attempt the limits let through, including for a name with no account, which spends a hash on a random password so both take the same time | The [rate limits](#rate-limiting) are checked first: 5 a minute per account and per typed name, 20 a minute per IP address, with locks that double. An attempt the IP address's limit refuses hashes nothing. One the account's own limit refuses quietly still spends a hash, so it takes as long as a wrong password, and so does one a typed name's limit refuses with a `429`: behind a refused name the password is either checked or a hash is spent in its place, so the `429` costs the same whether the name has an account, and whether that account's limits were cleared since. The IP address's limit bounds how many of those one address can ask for. Hashing a new password on registration, a change or a reset is behind the `keyring` limiter, 6 a minute. |
| A worker held for `timebox` (500ms) | Every refused verification, a `429` included | It's a sleep, not CPU, but it does hold a PHP worker, and Keyring doesn't bound how many: a rate-limited request waits like any other refusal, or the limits would show in the timing. What bounds it sits in front of PHP: the connection and request limits of your web server or load balancer, and the size of the worker pool. Lowering `timebox` gives each worker back sooner and makes timing less even. |
| The breached-password lookup, an HTTPS request to Have I Been Pwned | Setting a password, in production by default (`passwords.uncompromised`); and at every password sign in if you add the `BreachedPassword` risk signal, which isn't on by default | Behind the `keyring` limiter for new passwords, and the sign-in limits for the signal. Laravel's verifier gives up after 30 seconds and then lets the password through, so an outage slows these requests rather than failing them. With `passwords.refuse_unchecked`, Keyring asks itself, gives up after 10 seconds and refuses the password. Turn the check off, or bind an `UncompromisedVerifier` of your own with a shorter timeout, if that's too long to hold a worker. |
| WebAuthn verification: decoding the response and checking one signature | Adding a key, and every sign in or step-up with one | At sign in, the factor's rate limits, checked before the response is read; adding a key is behind the `keyring` limiter and a fresh verification. Usernameless options are limited to 60 a minute per IP address. An RSA key is bounded to 16,384 bits by the library, since the work grows with the key. |
| Attestation: a certificate chain of at most six, checked against each root you list for the model | Adding a key to a factor with `requireAttestation()` | The `keyring` limiter on enrollment, the cap on chain length, and nothing being fetched: no revocation lookups, no metadata download. |
| Mail | A reset link, an email change, a verification link, an emailed code, a security notice | Reset and email-change mail is sent after the response. A verification link and an emailed code are sent during the request, unless you queue those notifications: a code is limited to three per factor every 10 minutes per account (`limits.codes`). The published security notices are queued, five of a kind an hour per account (`limits.notices`). The routes that ask for mail are behind the `keyring` limiter. |
| The risk signals' lookups: a few indexed queries on the security log, the account's devices and its sessions | A sign in that gets its first factor right, for the signals the published provider turns on, and one comparison of browser names on each signed-in request | They run after a correct first factor, which the rate limits bound. Each signal is a line in your provider to take out. |
| A session lock | Sign in, challenge and enrollment routes | Requests in one session wait for each other, for up to Laravel's 10 seconds, and one that waited that long fails. One session can't hold up another. |

## Standards

Keyring's code and config say what each thing does. This is where the choices come from. A row that says Keyring departs from a requirement has its reason under [Known Limitations](#known-limitations), and [OWASP ASVS and NIST SP 800-63B](owasp-asvs.md) has the standards the other way round: every requirement, and what Keyring does about it.

| What Keyring does | From |
|---|---|
| **Assurance levels and sessions** | |
| Assurance levels, and what reaches AAL2 and AAL3, as far as a library can check. AAL2 takes two kinds of factor, one of them something the user has. AAL3 takes an attested key that can't leave its device, with its own user verification or a password. Validated authenticators and verifier cryptography, which NIST AAL3 also needs, are yours to supply | NIST SP 800-63B-4, Sec. 2.2.1, 2.3.1, 2.3.2 and Appendix B |
| Each level lapsing after idle and overall limits (AAL2: 1 hour, 24 hours; AAL3: 15 minutes, 12 hours). The session carries on at the level that's left, or ends with `sessions.end_on_lapse` | NIST SP 800-63B-4, Sec. 2.2.3, 2.3.3, 5.1 and 5.2. Carrying on departs from Sec. 5.2 |
| An idle and an absolute timeout on every session, kept on the server, with a longer idle one for "remember me" as a stated decision | OWASP ASVS 5.0.0, 7.3.1 and 7.3.2, and OWASP's Session Management Cheat Sheet. "Remember me" departs from NIST SP 800-63B-4, Sec. 5.1 |
| A new session ID, and the old session ended, on every sign in and step-up | OWASP ASVS 5.0.0, 7.2.4 |
| A session that is signed out, revoked or timed out can't be used again | OWASP ASVS 5.0.0, 7.4.1 |
| A deleted user's sessions end with them, and an account the app keeps out loses all of its sessions the first time one of them makes a request | OWASP ASVS 5.0.0, 7.4.2 (for ending them sooner, see [Who May Sign In](sign-in-flow.md#who-may-sign-in)) |
| A stated number of sessions per account, and what happens at it | OWASP ASVS 5.0.0, 7.1.2 |
| The option to end other sessions after any change to a sign-in method | OWASP ASVS 5.0.0, 7.4.3 |
| A command for administrators to end one user's sessions or everyone's | OWASP ASVS 5.0.0, 7.4.5 |
| Users seeing their sessions, and ending any or all of them after verifying again | OWASP ASVS 5.0.0, 7.5.2 |
| A "remember me" cookie that works once, with a used one ending the session | Refresh token rotation with reuse detection (RFC 9700, Section 4.14.2), applied to a cookie, and OWASP's Session Management Cheat Sheet for revoking every rotated ID of a session together |
| **Rate limits** | |
| A cap of 100 failures in a row on each of an account's authenticators, kept in the database, after which it's refused until it's set up again. A lower number for browsers the account hasn't signed in from is one of the additional, risk-based techniques NIST allows for keeping an attacker from locking the owner out. `Keyring::unlock()` switches an authenticator back on without binding it again, which NIST doesn't provide for | NIST SP 800-63B-4, Sec. 3.2.2 |
| Locks that double each time, and a count of its own for the browsers the account has signed in from | OWASP's Authentication Cheat Sheet (exponential lockout) and the OWASP Community page "Slow Down Online Guessing Attacks with Device Cookies", adapted: known browsers share one bucket, and the cookie is a random token stored hashed |
| Limits per account, per typed username and per IP address on every factor, and a limiter on the other forms | OWASP ASVS 5.0.0, 2.4.1 and 6.3.1, and OWASP's Credential Stuffing Prevention Cheat Sheet |
| **Passwords** | |
| Password lengths: 8 with a second factor, 15 without, and no setting below 8 | OWASP ASVS 5.0.0, 6.2.1, and NIST SP 800-63B-4, Sec. 3.1.1.2 (15 for a password used alone, 8 as part of multi-factor) |
| A password change taking the current password as well as the new one | OWASP ASVS 5.0.0, 6.2.3 |
| Refusing the most common passwords: the top 10,000 of 8 characters or more and the top 3,000 of 15 or more | OWASP ASVS 5.0.0, 6.2.4 (at least the top 3,000 that fit the policy) |
| No composition rules, and any characters accepted | OWASP ASVS 5.0.0, 6.2.5, and NIST SP 800-63B-4, Sec. 3.1.1.2 |
| Passwords of at least 64 characters allowed, never silently cut short: up to `passwords.max` with argon2id, 72 bytes with bcrypt | OWASP ASVS 5.0.0, 6.2.9, and NIST SP 800-63B-4, Sec. 3.1.1.2. Met with `HASH_DRIVER=argon2id`, not with bcrypt |
| Refusing passwords made up of the app's name, the words in `passwords.context`, or the user's name and email address, comparing the whole password | OWASP ASVS 5.0.0, 6.2.11, with 6.1.2 for the list, which is yours to fill in; NIST SP 800-63B-4, Sec. 3.1.1.2, for comparing the whole password |
| Refusing breached passwords, in production by default | OWASP ASVS 5.0.0, 6.2.12, and NIST SP 800-63B-4, Sec. 3.1.1.2 |
| Passwords of any Unicode characters, normalised to NFC before hashing | NIST SP 800-63B-4, Sec. 3.1.1.2. This departs from the letter of OWASP ASVS 5.0.0, 6.2.8 (verified exactly as received): nothing is truncated or has its case changed, but the bytes are normalised |
| Passwords never expiring, and a user held until they choose a new one on evidence of compromise: when your app says so, and by default when the `BreachedPassword` signal finds the password just used in a breach | NIST SP 800-63B-4, Sec. 3.1.1.2 |
| **Factors and codes** | |
| Passkeys and security keys as a phishing-resistant option | NIST SP 800-63B-4, Sec. 2.2.2 and 3.2.5 |
| Email codes being opt-in, and counting toward no level: a password and an emailed code is AAL1 | NIST SP 800-63B-4, Sec. 3.1.3.1, which doesn't accept email as an authenticator, and OWASP ASVS 5.0.0, 6.3.6 |
| Two factors of the same kind not counting as two, and no weaker fallback for a user with a phishing-resistant factor | OWASP's Multifactor Authentication Cheat Sheet |
| Making everyone add a second factor with `keyring.enrolled`, which the installer sets up once a second factor is picked | OWASP ASVS 5.0.0, 6.3.3 |
| Proving the strongest combination the account can give before adding a sign-in method, whatever the sign-in policy asks | NIST SP 800-63B-4, Sec. 4.1.2.1 |
| A recent verification before changing how someone signs in | OWASP's Authentication Cheat Sheet, and OWASP ASVS 5.0.0, 7.5.1 |
| Single-use codes: random, short-lived, limited guesses, stored hashed, a resend replacing the last, and bound to the sign in they were sent for | OWASP's Multifactor Authentication Cheat Sheet (One-Time Password Handling and Storage), and OWASP ASVS 5.0.0, 6.6.2 and 6.6.3 |
| TOTP codes, recovery codes and sent codes that work once, whatever the session driver | OWASP ASVS 5.0.0, 6.5.1 |
| Recovery codes with at least 112 random bits, which is what lets them be kept as keyed hashes rather than salted password hashes | OWASP ASVS 5.0.0, 6.5.2 |
| Sent codes of at least six digits, that last ten minutes at most | OWASP ASVS 5.0.0, 6.5.4 and 6.5.5 |
| TOTP codes accepted one time step either side of now, and no further | RFC 6238, Section 5.2 (one step back for delay) and Section 6 (a limit on drift either way). This default departs from OWASP ASVS 5.0.0, 6.5.5 (a 30 second maximum), which a window of zero meets |
| A passkey challenge of 32 random bytes that runs out on the server and is answered once | OWASP's Passkey Security Cheat Sheet, and OWASP ASVS 5.0.0, 6.7.2 |
| A sign-in method presented with when it was added and last used | OWASP's Passkey Security Cheat Sheet |
| ES256 and EdDSA signatures by default, and RS256 only when asked for, with keys of 2048 bits at least | OWASP ASVS 5.0.0, 11.2.3 and 11.6.1, and RFC 8812, Section 2 |
| **Notices and risk** | |
| The emails Keyring sends about changes: password changed, sign-in method added or removed, recovery code used, new recovery codes, and with `Features::emailChanges()`, email address changed and an email change undone | NIST SP 800-63B-4 (Sec. 4.1.2.1, 4.2.1.1, 4.2.3, 4.5 and 4.6), OWASP's Forgot Password, Multifactor Authentication and Passkey Security Cheat Sheets, and OWASP ASVS 5.0.0, 6.3.7 |
| The emails it sends about suspicious attempts: a failed second factor, a sign in after several failures or a long quiet period, an account locked, what the risk signals add up to, and with `Features::devices()`, a new device | OWASP ASVS 5.0.0, 6.3.5, and OWASP's Multifactor Authentication and Credential Stuffing Prevention Cheat Sheets |
| A line saying who to contact in every security notice, the emailed code and the email change notice, once `support_contact` is set | NIST SP 800-63B-4, Sec. 4.6 |
| Risk signals in the published provider, at sign in and on every request: failure history and a session changing browser as installed, and the device signals with `Features::devices()` | OWASP ASVS 5.0.0, 8.2.4, and OWASP's Authentication and Session Management Cheat Sheets |
| **Account changes and registration** | |
| Registration that answers the same for every address | OWASP ASVS 5.0.0, 6.3.8 |
| Password resets: the same answer for every address, links built from `APP_URL`, no automatic sign in, every session signed out, second factors left as they are | OWASP's Forgot Password Cheat Sheet, and OWASP ASVS 5.0.0, 6.4.3 |
| The conformance suite failing an app whose password broker has no `throttle` | OWASP's Forgot Password Cheat Sheet (rate limiting per account) |
| Email changes confirmed from both addresses, and not trusting an address that just changed | OWASP's Authentication Cheat Sheet (changing a registered email address) and Forgot Password Cheat Sheet (recovery after suspected compromise) |
| **Headers, cookies and links** | |
| Never caching auth pages and responses | OWASP's Session Management Cheat Sheet |
| `X-Content-Type-Options: nosniff` and a referrer policy on every Keyring response | OWASP ASVS 5.0.0, 3.4.4 and 3.4.5 |
| `X-Frame-Options: DENY` on every Keyring response, unless the app's own policy says who may frame it | OWASP's Clickjacking Defense Cheat Sheet. OWASP ASVS 5.0.0, 3.4.6, asks for `frame-ancestors` in a content security policy, which is your app's to send |
| `Secure` cookies with the `__Host-` prefix | OWASP ASVS 5.0.0, 3.3.1 and 3.3.3, and OWASP's Session Management Cheat Sheet |
| Cookie names that say what the cookie is for and not what set it (`known_device`, `remembered_session`) | OWASP's Session Management Cheat Sheet, on session ID name fingerprinting |
| No referrer from pages whose URL holds a token | OWASP's Forgot Password Cheat Sheet |
| Emailed links that only act on a `POST`, with the token or signature in its body | OWASP ASVS 5.0.0, 3.5.3, and 14.2.1 for the request that acts (the emailed link itself still has to carry its token in the URL once), and OWASP's Cross-Site Request Forgery Prevention Cheat Sheet |
| Passwords, codes, credentials and tokens read from the body, never the query string of a `POST` | OWASP ASVS 5.0.0, 14.2.1 and 15.3.7 |
| The browser package encoding what it puts in a URL path | OWASP ASVS 5.0.0, 1.2.2 |
| Keyring's own breached-password lookup following no redirect (the default lookup is Laravel's, which follows them) | OWASP ASVS 5.0.0, 15.3.2 |
| A `Cross-Origin-Opener-Policy` on every Keyring response | OWASP ASVS 5.0.0, 3.4.8 |
| **Logging and storage** | |
| Logging sign ins, failures, lockouts, sessions "remember me" carried on and session ends by default, and what was refused: someone else's record, a link's token or signature, a rate-limited form, a skipped pipeline step | OWASP ASVS 5.0.0, 16.3.1 to 16.3.3 |
| A severity and a request ID on every entry, no secrets in any, and a cap on entries a refused request can cause | OWASP's Logging Cheat Sheet |
| A list of what's stored and how it's protected, deleted on a schedule Keyring sets up itself | OWASP ASVS 5.0.0, 14.1 and 14.2.7 |

## Known Limitations

### Where Keyring Departs From a Standard

Each of these is a choice. The reason is given once, here, and the [requirement-by-requirement page](owasp-asvs.md) says what each means for an app that has to meet the requirement.

- **A default install doesn't require a second factor.** Keyring starts with the password and leaves the rest to turn on, so with the installer's default answers there's nothing to require, and OWASP ASVS 5.0.0's requirement 6.3.3 (Level 2) isn't met. Which second factor your users get is your choice to make: pick one and the installer requires it of everyone unless you say otherwise, and the published provider has each one commented out for an app that adds it later.
- **Not every suspicious sign in is announced as installed.** OWASP ASVS 5.0.0's requirement 6.3.5 lists a sign in from an unusual client or place among them. A new device and a long quiet period are only known with `Features::devices()`, and a place only with a locator you supply, so a default install announces neither. A sign in after several failures is announced from the start, and a failed second factor once there is one.
- **Passwords are normalised before they're hashed.** OWASP ASVS 5.0.0 requirement 6.2.8 has a password verified exactly as received. Keyring cuts nothing short and changes no case, but it does put every password in Unicode's NFC form first, as NIST SP 800-63B-4 recommends (Sec. 3.1.1.2). The same "é" is one code point from some keyboards and two from others, and without this a password set on one device could fail on another.
- **Bcrypt stops passwords at 72 bytes.** It's Laravel's default hasher, and it ignores everything after the first 72 bytes, so with it Keyring refuses a longer password: 72 plain characters, but as few as 18 emoji, whatever `passwords.max` says. OWASP ASVS 5.0.0 requirement 6.2.9 asks for at least 64 characters, of any kind, to be allowed, and NIST SP 800-63B-4 recommends the same (Sec. 3.1.1.2). Set `HASH_DRIVER=argon2id` for that. Keyring doesn't pre-hash passwords to fit, which would leave hashes Laravel's own hasher can't check. See [Passwords](configuration.md#passwords).
- **By default a TOTP code works for longer than OWASP ASVS allows.** ASVS 5.0.0 requirement 6.5.5 gives a time-based one-time password a maximum lifetime of 30 seconds. Keyring accepts a code one time step either side of now unless told otherwise, so one code can work for up to about 90 seconds, and as shipped it does not meet that requirement. The default follows RFC 6238, which recommends accepting one earlier step for the time a code takes to arrive (Section 5.2) and allows a limit on clock drift either way (Section 6): with none, a code typed near the end of its 30 seconds fails, and so does every code from a phone whose clock is half a minute out. A code still works only once. To meet 6.5.5 exactly, register the factor with [a window of zero](factors.md#authenticator-apps-totp). A window wider than one step is refused.
- **TOTP codes are made with HMAC-SHA-1.** OWASP ASVS 5.0.0 lists it as a legacy algorithm (Appendix C, requirement 11.4.1). It's the default because it's the only digest every authenticator app makes, and several ignore a request for another without saying so, which would leave their users with codes that never work. Where you know your users' apps, [set the factor up with SHA-256 or SHA-512](factors.md#authenticator-apps-totp).
- **Windows Hello keys that only sign RS256 aren't taken by default.** RS256 isn't an algorithm OWASP ASVS approves, so `webauthn.algorithms` leaves it out, and on a machine whose Windows Hello makes nothing else, a passkey can't be created with it. See [RS256 and Windows Hello](passkeys.md#rs256-and-windows-hello) for who that affects and how to turn it on. Turning it on, or requiring attestation, whose makers sign their certificates the same way, takes Keyring outside ASVS's requirements 11.2.3 and 11.6.1.
- **Attestation is off unless you ask for it, only covers hardware keys, and checks no revocation list.** By default any WebAuthn authenticator is accepted and AAGUIDs aren't verified, so no session reaches AAL3. A factor set up with `requireAttestation()` checks `packed` and `fido-u2f` attestation against root certificates you list, and can then be limited to certain models. Platform formats (`tpm`, `android-key`, `apple`) aren't read. OWASP's Passkey Security Cheat Sheet has a verifier check a chain's status too: Keyring fetches nothing while a key is being added, so a maker's certificate that has been revoked is still accepted until you take its root out of your list. See [Attestation and AAGUIDs](passkeys.md#attestation-and-aaguids).
- **A used recovery code isn't replaced automatically.** NIST SP 800-63B-4 (Sec. 4.2.1.1) has a new code issued after each use. Keyring uses the code up and stops there, because a new one is only worth something once its owner has seen and saved it, and a sign in is no place to show it. The set says a code has been used (`shouldReplaceRecoveryCodes()`), and the rule is met once your app sends the user to [make a new set](authenticators.md#recovery-codes).
- **"Remember me" signs a browser back in without a factor.** NIST SP 800-63B-4 (Sec. 5.1) doesn't accept a cookie in place of authentication. A browser that ticked "remember me" comes back signed in after its session idled out, for up to 14 days (`sessions.remember_idle`), because that is what the checkbox is for. Keyring ties the cookie to the session it was ticked for, lets it work once and gives the session it resumes no assurance level, so routes behind `keyring:aal1`, `keyring:aal2` or `keyring.fresh` ask again, but a route behind `auth` alone is reached on the cookie. Where you follow that section, leave the checkbox off your login form or set `sessions.end_on_lapse`. See [Inactivity and "Remember Me"](devices-and-sessions.md#inactivity-and-remember-me).
- **A session outlives its assurance level.** NIST SP 800-63B-4 (Sec. 5.2) ends a session when its inactivity or overall timeout passes. By default Keyring lowers the session's level instead: a session that signed in with two factors stops being AAL2 after an hour idle or 24 hours and carries on as AAL1, under the limits every session has. Sec. 5.1 allows a session to be treated as a lower level, and ending it would sign out the people who set up a second factor after an hour away while leaving everyone else signed in for 30 days. `sessions.end_on_lapse` ends it. See [Ending a Session With Its Level](devices-and-sessions.md#ending-a-session-with-its-level).
- **An account has one email address.** NIST SP 800-63B-4 asks for at least two addresses to send notices to (Sec. 4.6) and two to recover an account through (Sec. 4.2.1.2). Keyring knows the one in your user model's `email` attribute: it's where reset links, emailed codes and security notices go. A library with one attribute to read can't supply a second. To send every notice to more than one address, return them from `routeNotificationForMail()` ([A Support Contact](security-log-and-emails.md#a-support-contact) shows how). A second address that can recover the account, verified before it's used, is your app's to build.
- **A notice doesn't say who to contact until you say where.** NIST SP 800-63B-4 (Sec. 4.6) has a notice carry contact information. Keyring's notices have the line and leave it out while [`support_contact`](security-log-and-emails.md#a-support-contact) is `null`, since only you know where your support is.
- **No pepper.** NIST SP 800-63B-4 (Sec. 3.1.1.2) and OWASP's Password Storage Cheat Sheet recommend one. See [Peppering Passwords](#peppering-passwords) for why it isn't built in and how to add it.
- **The breach check fails open by default.** Laravel's check lets a new password through when Have I Been Pwned can't be reached, leaving the bundled list of common passwords, so that an outage elsewhere doesn't stop registrations. OWASP ASVS 5.0.0's requirement 16.5.3 counts a check that passes on an error as failing open, and 16.5.2 asks that an outside service failing leaves the app secure. Set `passwords.refuse_unchecked` to refuse the password instead, at the cost of no new passwords while the service is unreachable. Outside production the check doesn't run at all unless `passwords.uncompromised` is `true`.
- **The per-minute limits are kept in the cache.** Clearing the limiter's cache store starts the per-minute counts over and lifts their locks and risk locks, which OWASP ASVS 5.0.0's requirement 16.5.3 counts as failing open. A count on every attempt belongs somewhere fast, and what ends guessing doesn't depend on it: the failures in a row and the locks held until a reset are in your database. See [Rate Limiting](#rate-limiting).
- **An emailed link carries its token in its URL.** It has to, and OWASP ASVS 5.0.0's requirement 14.2.1 doesn't allow for it. See [Tokens in Emailed Links](#tokens-in-emailed-links) for what Keyring does about it, and why the reset link carries the address too.
- **Stored hashes don't say which scheme made them, and session registry IDs aren't hashed.** See [Changing an Algorithm](#changing-an-algorithm) and [Algorithms](#algorithms).
- **Form validation failures aren't logged.** OWASP ASVS 5.0.0's requirement 16.3.3 and OWASP's Logging Cheat Sheet list them among what to log. A missing field or a malformed address is an ordinary mistake and says nothing about an attempt on an account, and logging each would bury what does. Everything Keyring refuses for a reason is logged.
- **The log table's times have no offset.** OWASP ASVS 5.0.0's requirement 16.2.2 wants UTC or an explicit offset. `keyring_events.created_at` is a plain timestamp in your `app.timezone`, as every Laravel timestamp is. Leave `app.timezone` at UTC, its default. See [Times](security-log-and-emails.md#times).
- **A disabled account's sessions end when one of them is next used.** OWASP ASVS 5.0.0's requirement 7.4.2 ends them when the account is disabled. Keyring doesn't know that moment, because the flag is your app's: call `Sessions::signOutEverywhere()` as you set it. See [Who May Sign In](sign-in-flow.md#who-may-sign-in).
- **No bot check.** See [Bot Checks](#bot-checks).

### Other Limits

- **The undo link for an email change trusts the old mailbox.** It has to: it's there for an owner who has nothing else left. So someone who reads the old mailbox can undo a change the owner made, which also removes sign-in methods added in the week before it or since the session that asked signed in, and can then reset the password by email. A second factor older than that survives. See [Reverting](protected-changes.md#reverting) for why the line sits there and how to move it.

- **The `cache` session registry is as good as its store.** A session's record says whether it was revoked or replaced, and so does a key beside it, so losing either leaves the session ended. The list of a user's sessions is one key, though, and a store that drops it (Redis or Memcached evicting under memory pressure, a replica promoted without its latest writes) leaves those sessions out of the sessions list and of a sign-out everywhere until they next expire. Use a store that doesn't evict, or the `database` driver, which is the default.
- **Lockouts still reach new browsers.** Someone who knows a user's email can keep that account locked by guessing faster than the per-minute limit, and after 80 wrong passwords in a row (20 minutes at the quickest) the password is refused from every browser the account hasn't signed in from until its owner resets it. See [At the Cap](#at-the-cap). If they guess under one of the account's names and the owner types another, the owner is told the password is wrong rather than to wait, because saying more would tell a stranger the two names are one account. With `Features::devices()` on, browsers the owner has signed in from before keep their own limit and keep working. Without devices, the lock reaches every browser while the guessing goes on, and so does the cap. A password reset clears the password's counts and locks, but not a second factor's.
- **Which browsers are known is kept in the cache.** A browser stops counting as known when the account is taken back, and that's recorded in the limiter's cache store with the mark a reset replaces. If the store loses its keys, a browser from before the reset counts as known again. It still can't pass the cap: known browsers and everyone else share it.
- **A run of failures can begin with a few at once.** Once a kind of browser (the account's own, or everyone else) has failures on record, each of its attempts is counted before its proof is looked at. Its first aren't, so that an ordinary sign in writes nothing, and as many as the per-minute limit lets through at once (`limits.per_account`, 5) can be checked together. Each is counted when it fails. With the defaults that can't pass the cap. It could if `limits.consecutive_elsewhere`, or what's left of `limits.consecutive` above it, were set lower than `limits.per_account`.
- **No clone detection for synced passkeys.** Their counters are usually always zero.
- **Protection only covers Eloquent saves.** Query builder updates and `saveQuietly()` skip the protected attribute check.
- **Changing `APP_KEY` invalidates short-lived data.** Pending email codes stop working, and a user's first passkey after the change gets a different user handle (later ones reuse the handle their keys already have). Recovery codes and reserved email addresses keep working when the old key is in `APP_PREVIOUS_KEYS`, as encrypted values such as TOTP secrets do.
- **Signing out ends "remember me" in every browser.** Laravel has one remember token per user, so signing out, revoking any device or signing out other sessions ends every remembered browser. A session that times out, that the user ends from their [sessions list](devices-and-sessions.md#listing-and-ending-sessions), or that Keyring ends for another reason, only ends its own.
- **A copied "remember me" pair is only caught when both holders use it.** Whoever comes back first gets the session, and it ends when the other one turns up: with the used cookie, or still signed in on the old record. A copy made of a browser that never comes back is not noticed, and lasts until the session's `absolute` limit. Inside `sessions.remember_grace` a copy sent from what looks like the same browser joins the session instead, and is caught the next time either of them comes back. A browser that never received the response carrying its new cookie looks like a copy the next time, and has to sign in again.
- **"Remember me" expects one session store per browser.** Two apps that share the cookies and the registry but keep separate Laravel sessions would each see the other's return as a used cookie.
- **Laravel's `cookie` session driver can't destroy an old session.** The session lives in the cookie, so nothing on the server can delete a copy of one. Keyring ends copies through the registry instead: a sign in, a step-up, a password change, signing out everywhere else and an applied email change all move the session to a new registry record and revoke the old one, and signing out revokes it, so a copy made before any of them is signed out on its next request. Three things remain. A copy keeps working until the next of those happens, or the session is revoked or times out, because until then it's the same cookie as the original. It's only turned away where the [session middleware](devices-and-sessions.md#the-session-middleware) runs. And a sign in that isn't finished has no record to swap, so the ID changes between its steps leave an earlier copy holding the pending login as it was, which the next entry covers. A server-side session driver has none of the three.
- **The `cookie` session driver lets a browser send back what its session held.** With that driver the session lives in the browser, so it can send an earlier copy of its own cookie, and a pending login or enrollment is kept in the session. Nothing that must happen only once depends on it. TOTP steps and recovery codes are used up in your database. A sent code, its wrong guesses, the code that replaced it, each enrollment's one confirmation and each WebAuthn challenge's one answer are kept in your cache, with the limits on attempts per account and per IP address and codes sent, and failures in a row are counted in your database. Two things remain. An earlier copy returns a pending sign in or step-up to an earlier point, which only means proving a factor again: a WebAuthn challenge it still holds was either never answered, and is as good as it was, or was answered, and is refused. And what the cache remembers lasts as long as the cache does. If the rate limiter's store is cleared or drops keys, an answered challenge that hasn't yet expired (5 to 15 minutes from when it was issued) is forgotten, and whoever holds both an earlier copy of the session and the signed answer the key gave could send that answer again. A key that counts its signatures still refuses it, because the count hasn't moved on. A synced passkey, whose count stays at zero, would be accepted. The same goes for a used code and a confirmed enrollment, so keep that store somewhere [your deploys don't clear](#rate-limiting). A server-side session driver has neither: the challenge is gone from the one session there is.
- **A request overlapping a session ID change can undo or lose it.** Laravel saves the session when each request ends, so a request still running when the ID changes can save the old session again, and a copied cookie would then keep working. A request sent with the old ID just after the change finds no session, and that browser has to sign in again.
- **Location signals need trustworthy data.** `HeaderLocator` trusts request headers, so only use it behind a proxy that sets them and can't be bypassed.
- **Session guards only.** Pending logins and step-up live in the session, so stateless API clients and mobile apps can't use the sign in flow directly.
- **Work in progress.** Keyring hasn't been tagged or used in production yet.
