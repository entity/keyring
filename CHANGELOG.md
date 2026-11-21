# Release Notes

## Unreleased

### Sessions and Devices

- `sessions.continue_as_guest` lists routes that also serve guests. A page visit to one whose session has ended is signed out and asked for again as a guest, rather than sent to log in, whatever the reason it ended. The `signed-out` status is flashed and no intended URL is saved. JSON requests still get a `401`.

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
