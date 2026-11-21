# Release Notes

## Unreleased

### Sessions and Devices

- A session keeps its handle when it moves to a new record: when "remember me" carries it on, when a risk response asks it to verify again, and with `rotate` on the `cookie` session driver. Each record names the one the session started on (`origin`), and the handle comes from that. Sessions that started before the upgrade keep the handles they had. Needs a new migration, see the [upgrade guide](UPGRADE.md).
- `Sessions::stillSignedIn($user, $handle)`, for code that knows a session by its handle to ask whether the user is still signed in on it. It applies `Keyring::allowSignInWhen()` and the session's timeouts, and it changes nothing.
- A conformance check that the session registry keeps `origin` when a session moves, so a missing migration or a custom driver that drops it is caught in your tests.
- The session registry says which records it revoked. `revoke()` returns the record it revoked, or `null` when it revoked nothing, and `revokeAll()` and `revokeDevice()` return the records they revoked instead of a count. Custom registry drivers need to return them too: see the [upgrade guide](UPGRADE.md#from-02-to-03). `Sessions::signOutEverywhere()`, `Sessions::revokeDevice()` and the `SessionsRevoked` event still give a count.
- The conformance suite checks that the configured registry returns the records it revoked.
- A `RegisteredSessionEnded` event for every registered session that ends, whoever ends it and wherever: signing out, the app's own `Auth::logout()` or `Auth::logoutCurrentDevice()` (announced as `logged_out` unless the app gives a reason of its own with `Sessions::because()`), signing out everywhere, ending a session or a device, the device and session limits, a deleted user, a risk response, a password change or reset, an email change or its undo, and the session middleware finding a session idle, expired, used twice or kept out. It names the session by its handle, with the handle under each previous app key too, and says why it ended (`Keyring\Enums\SessionEndReason`). It never carries the registry ID. On the `database` driver it goes out once the transaction it was revoked in commits, and not at all if that's rolled back. A listener that throws is reported and doesn't stop the sign-out. See [Hearing About Ended Sessions](docs/devices-and-sessions.md#hearing-about-ended-sessions).
- An `EveryoneSignedOut` event when `keyring:sign-out --all` or the registry's `revokeEveryone()` ends every user's sessions at once.
- Every registry driver, a custom one included, is wrapped in `AnnouncingSessionRegistry`, which dispatches those events from what the driver returns. `app(SessionRegistry::class)` returns the wrapper, and its `inner()` the driver. See the [upgrade guide](UPGRADE.md#the-session-registry-is-wrapped).
- A conformance check that signing out announces the session that ended, which fails when a `SessionRegistry` is bound in the container without the wrapper.
- A driver that fails after revoking some of a user's records throws a `PartialRevocation` with the ones it revoked, so they're still announced. The `cache` driver does this when the store fails part way through signing out everywhere, and keeps a revocation whose copy into the record fails. On the `cache` driver only, what a synchronous listener wrote on the user's connection is kept too, when Keyring's row lock is the outermost transaction: inside one of the app's own, the failure still rolls it back unless the app catches it. A database failure, deadlocks and lost connections included, always rolls it back. On the `database` driver with the registry on the user's connection, the failure rolls back the whole change, a sign in's new record included. With the registry on a `sessions.connection` of its own, it behaves as the `cache` driver does. On either driver, signing out everywhere still cycles the remember token, stops trusting devices and cancels a pending email change before the failure is thrown, signing a device out still cycles the remember token, and signing out everywhere else still gives this session a new ID.
- Registry IDs are marked `#[\SensitiveParameter]` on the contract, both drivers and `Sessions`, so they stay out of reported stack traces.
- `keyring:sweep`, which ends sessions that timed out with no request to end them and announces them as `idle` or `expired`, and announces again any ended session whose event was lost, so every ended session is announced at least once on the `database` driver. Turn it on with `sessions.sweep_every`, and Keyring schedules it before the prune, on one server and never overlapping. One run announces again, and ends, at most `sessions.sweep_limit` (1000) sessions each. A listener that throws is tried again five minutes later, then at doubling intervals for a day. Needs a new migration, see the [upgrade guide](UPGRADE.md#sweeping-ended-sessions).
- Once the new migration has run, `keyring:prune` keeps sessions a sweep still has to end or announce, whether or not one is scheduled. An expired session nobody ended stays up to a day longer before the prune removes it, and so does one the sweep ended for timing out, so its browser is still told why.
- `keyring:sign-out --all` marks the sessions it ends for its `EveryoneSignedOut`, so the sweep never announces them one by one, and counts them announced once the event has gone out. If it didn't, the sweep dispatches `EveryoneSignedOut` again, up to a day later, the latest of any lost ones, which settles the rest. Its `at` is a cut-off on sign-in time, never "end everything now".
- With the migration run, a record "remember me" moved a session to stays until it expires, so a used cookie still raises `RememberMeReused` after the sweep ended its session and the prune ran.
- `RememberMeReused` now also fires when the session a used cookie was carried on to has timed out since, so a sweep ending that session doesn't hide the reuse. The used record is revoked then, so the same cookie is reported once.
- A browser that comes back after its session was revoked once it had timed out, by the sweep or by signing out everywhere, is signed out as `idle` or `expired`, in `SessionEnded` and the security log, as it would be had nothing revoked it first. It used to say `revoked`. One the sweep ended keeps saying so until a day after its expiry. One signed out everywhere says so until the prune removes its record, a day at most.
- The database registry driver rethrows a failed query without its bindings, so record IDs, which are what "remember me" cookies hold, stay out of exception messages, logs and error trackers. `PartialRevocation` no longer repeats the failure's message.
- On the `cache` driver, revoking a record and moving it with "remember me" take turns under the owner's lock (on a store with locks), so a sign-out that lands mid-move is never lost without an event. A revocation that can't have the lock within five seconds goes ahead without it. On a `database` cache store, a failed cache query is rethrown without the cache keys it named, which hold record IDs.
- Signing out signs the browser out even when the session registry fails to revoke its record. The failure is still thrown, but the next request is a guest, where it used to be registered as a new session.
- `sessions.continue_as_guest` lists routes that also serve guests. A page visit to one whose session has ended is signed out and asked for again as a guest, rather than sent to log in, whatever the reason it ended. The `signed-out` status is flashed and no intended URL is saved. JSON requests still get a `401`.
- A sign-out your app does itself with `Auth::logout()` or `Auth::logoutCurrentDevice()`, on Keyring's guard in a request with a session, now ends the registered session too, with its "remember me" cookie and what the session proved. Before, the record stayed good until it timed out. On the `cookie` session driver, a copy of the session stayed signed in, and after `logoutCurrentDevice()`, so did a copy of its "remember me" cookies.

### Policies and Step-Up

- `StepUp::unlessMet()` to ask for step-up from a controller, for an integration that reads what to ask for from the request, such as an OpenID Connect provider with `acr_values` and `max_age`. It takes an `Assurance` level, a moment the user must have verified since, or both, and gives the same answer as the `keyring` and `keyring.fresh` middleware. Asking for nothing, or for a moment more than a few seconds in the future, throws.
- `StepUp::meets()` to ask the same thing without starting a step-up, for a request that mustn't show the user anything, such as one with `prompt=none`. It takes `unlessMet()`'s arguments and returns `true` where `unlessMet()` returns `null`, and leaves no confirm attempt or page to come back to in the session.
- `keyring:{level}` gives a guest Laravel's usual `AuthenticationException` even when the session still holds what the last user proved, as `keyring.fresh` already did. A session keeps that when the guard can no longer load its user, say because the account was deleted, and on a route without `auth`, the guest used to get through on it.
- The docs explain how to read what a session proved, for claims like `amr`, `acr`, and `auth_time`.
- `SessionAssurance::level()` and `countingToward()` take a timestamp, to count only what was proved since then with each level still on its own clock, so claims built for `max_age` don't report a level that lapsed.
- Users sent to enroll by `keyring.enrolled`, by step-up, or by the confirm page with nothing to confirm with now get the page they were going to back as `continue` on the `authenticator-added` status. Users held for a new password are redirected there by `password-updated`. Only top-level navigations and Inertia visits are remembered, and only on the app's own origin, for the same user, within an hour. Bind your own `Keyring\Login\Detours` and override `put()` to keep other pages out, such as `prompt=none` authorize requests.

### Logging and Emails

- A queued listener for `FactorChallenged` or `FactorVerified` now runs for an unsaved authenticator, such as the password's. It has nothing stored, so the job failed with a `ModelNotFoundException`. It's now queued as it is, without the user loaded with it, and a stored authenticator is still queued by its ID.
- An unsaved authenticator, such as the password's, now has its user's `authenticatable_type` and `authenticatable_id` set, so `owner()` finds the user, and `user()` looks them up again when they aren't loaded. Before, `owner()` ran a query Postgres refuses.
- `security_log.unlisted` lists entry types that `Keyring::activity()` leaves out, for entries a package writes about a user that aren't something the user did, such as a token issued to another app's server. They're still the user's entries: alerts, the log channel and a force delete treat them as before.

### Extending

- `StepUp` makes the decisions for the `keyring` and `keyring.fresh` middleware, and its constructor also takes a `DeviceManager`. What `keyring.fresh` asks for is `StepUp::freshRequirement()`, no longer the middleware's own `requirement()`. See the upgrade guide.

### Security

- A queued listener for `SessionResumed` or `RememberMeReused` no longer puts the session's registry ID on the queue. That ID is the value of the "remember me" cookie, so for `SessionResumed` it was a live one. Queued, the session's record now has a blank `id` and no `replacedBy` or `origin`, and both events always carry the session's `handle` to go by instead, the same one the sessions list shows. Listeners in the request see the record as before.
- Queueing a listener for an event that carries a sign in or step-up (`Authenticated`, `Confirmed`, `FactorChallenged`, `FactorVerified`, `VerificationRefused`) no longer puts the user's password hash and remember token on the queue. The attempt is queued as the plain data it keeps in the session and looks its user up again when asked. Jobs queued by 0.2 still restore, and drop the user they had cached.
- `AuthenticatorRemoved` now queues the user by ID like every other event, and the removed authenticator without its secret.

Restart your queue workers with the deploy. See the [upgrade guide](UPGRADE.md) for session events still on the queue, and for the old jobs in `failed_jobs` and Horizon.

## v0.2.0 - 2026-11-20

### Rate Limits and Risk

- A `CredentialStuffing` risk signal, off until you turn it on: a sign in from an IP address where five or more other accounts failed a factor in the last hour. It reads the security log, and the published provider lists it commented out. Keyring's own response emails the user whenever it fires, as it does for a sign in after several failures.

## v0.1.0 - 2026-11-18

The first release.

### Signing In

- Sign in, sign out, registration, password resets and email verification, with your own actions and pages.
- Registration that doesn't reveal who has an account: the same answer for a free and a taken address, even when your action fails to create the user, with new users signing in once they've verified theirs, from the browser that followed the link, which gets a new session ID for it. `registration.reveal_taken` says when an address is taken instead.
- Factors behind one contract: password, authenticator apps, passkeys, security keys, email codes and recovery codes, plus your own. Many authenticators per user, with a default and "try another way".
- Passkeys and security keys from one WebAuthn driver: ES256 and EdDSA by default, RS256 when you ask for it, a challenge that is answered once and runs out on the server, and sign in with Laravel's `@laravel/passkeys` client. Like Laravel's passkeys package, the options name the relying party by its ID, so there's no name to set.
- `WebAuthn::securityKeys()->requireAttestation()` to only add hardware keys whose attestation chains to root certificates you list, and `allowOnly()` to limit them to certain models by AAGUID.
- Authenticator app codes that work once, with SHA-1, SHA-256 or SHA-512, and a window of one time step or none.
- Email codes as an extra step at sign in. They are opt-in and never count as a second factor.
- Recovery codes of 128 random bits, stored as keyed hashes, with a flag that says when a used set should be replaced.
- `Keyring::attempt()` to start a sign in from your own route, for social logins and the like.
- `Keyring::allowSignInWhen()` to keep banned or unapproved accounts out, however they try to sign in. The first request it refuses ends every session the account has.
- A verification pipeline you can add steps to, with the steps that enforce Keyring's guarantees protected from being removed by accident.

### Policies and Step-Up

- Policies built from assurance levels that follow NIST SP 800-63B-4: AAL2 needs a factor the user has, and AAL3 an attested key that can't leave its device. `ifEnrolled()` and `noDowngrade()` say how a policy treats users who can't meet it yet, or who have a passkey.
- `keyring.enrolled` to make everyone set up a second factor, which the installer adds when you pick one.
- Step-up middleware: `keyring:aal2` and `keyring.fresh:15m`, with a shared confirm flow. Changing how an account signs in takes the strongest proof the account can give, and a recovery code only counts there beside another factor.

### Sessions and Devices

- A registry of signed-in sessions that works on any session driver: a list of the user's sessions to end one by one, signing out everywhere else, a limit on sessions per account, and idle and absolute timeouts kept on the server.
- Assurance levels that lapse on NIST's clock, with `sessions.end_on_lapse` to end the session with its level.
- "Remember me" tied to the session it was ticked for: it carries that session on and can't outlast its timeouts, a revocation or a risk response. Its cookie works once and is replaced each time. A used one sent again ends the session for everyone holding it, with a `RememberMeReused` event and a `remember_me_reused` log entry.
- Devices: trusted devices, new-device emails with a "this wasn't me" link, and a limit on devices per account.
- `Secure`, `__Host-` prefixed cookies named for what they do (`known_device`, `remembered_session`).
- `keyring:sign-out` to end one user's sessions or everyone's.

### Account Changes

- Protected `email` and `password` attributes, which only change through Keyring's flows once it handles them.
- Email changes confirmed from both addresses and revertable from the old one, with the old address reserved while they can be undone.
- Password changes that take the current password and are only saved over the one that was checked, and resets that sign nobody in, end every session and leave second factors alone.
- Password rules that follow OWASP ASVS 5.0.0 and NIST SP 800-63B-4: 15 characters alone or 8 with a second factor, no composition rules, a bundled list of the most common passwords, your own context words, a breach check that can refuse what it couldn't check, Unicode normalised to NFC, and, with bcrypt, a password it would cut short or can't hash refused.
- `Keyring::requirePasswordChange()`, and a risk action of the same name, to hold a user until they choose a new password when theirs is known to someone else.
- Emailed links that only act on a button press, with the token or signature posted in the body, built from `APP_URL` and opened on pages that send no referrer.

### Rate Limits and Risk

- Rate limits per account, per typed username and per IP address, with locks that double, a count of their own for browsers the account has signed in from, a cap on failures in a row kept in the database, and `limits.lock_after` to keep an account locked until its password is reset.
- A timebox around every verification, registration and refused password reset, so a refusal takes the same time whatever the reason.
- Risk signals with an action for each level: a new device, a new country, impossible travel, a session turning up in another browser, repeated failed second factors, a sign in after several failures or after a long quiet period, a recently changed email address and a password found in a breach. A new app starts with the ones its features can feed, and a password found in a breach holds its user until they choose another.

### Logging and Emails

- A security log with a severity and a request ID on every entry, of sign ins, sessions "remember me" carried on, failures, lockouts, changes and what was refused, capped so a refused request can't fill it, and written whatever text an entry is about. Without the table it goes to your app's log.
- "Was this you?" alerts at the next sign in.
- Security emails about changes to how an account signs in and about suspicious attempts, sent from the start as far as your features go. Each is a notification you can swap for your own or turn off, and `SecurityNotice::toMailUsing()` writes them all from your own template.
- `support_contact`, so every notice can say who to contact.
- `Keyring\Events\*` for everything above, with Laravel's own auth events raised beside them.

### Tooling

- `keyring:install`, which asks which sign-in methods and features you want and publishes a config, a provider and your actions. Its defaults give the password alone, and every other sign-in method is in the provider, commented out, to turn on later. Also `keyring:import fortify`, and `keyring:prune`, scheduled daily.
- Security headers on Keyring's responses: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy: same-origin-allow-popups` and a referrer policy.
- `Keyring::result()`, for a page to read what a form or Inertia response flashed for it, such as new recovery codes, which is kept encrypted in the session.
- Test helpers, a fake, factories, a virtual WebAuthn authenticator and a conformance suite that checks your setup still keeps Keyring's guarantees.
- `@keyringjs/keyring`, a browser package for WebAuthn, enrollment, sessions and the challenge page, with Vue and React bindings.
- Documentation of where Keyring stands on every requirement of OWASP ASVS 5.0.0 and NIST SP 800-63B-4 that bears on it, and of each place it deliberately does something else.
