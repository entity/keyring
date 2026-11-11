# Release Notes

## Unreleased

The first release. Nothing is tagged yet.

- Sign in, sign out, registration, password resets and email verification, with your own actions and pages.
- Registration that doesn't reveal who has an account: the same answer for a free and a taken address, with new users signing in once they've verified theirs.
- Factors behind one contract: password, authenticator apps, passkeys, security keys, email codes and recovery codes, plus your own.
- `WebAuthn::securityKeys()->requireAttestation()` to only add hardware keys whose attestation chains to root certificates you list, and `allowOnly()` to limit them to certain models by AAGUID.
- Many authenticators per user, with a default and "try another way".
- Policies built from assurance levels, with `ifEnrolled()` and `noDowngrade()`.
- Step-up middleware: `keyring:aal2` and `keyring.fresh:15m`.
- Devices and sessions: trusted devices, new-device emails with a "this wasn't me" link, and signing out everywhere else, on any session driver.
- "Remember me" tied to the session it was ticked for: it carries that session on and can't outlast its timeouts, a revocation or a risk response.
- Protected `email` and `password` attributes, with email changes confirmed from both addresses and revertable from the old one.
- Risk signals with an action for each level.
- A security log, "was this you?" alerts and security emails, each a notification published into your app.
- `keyring:install`, `keyring:import fortify` and `keyring:prune`.
- `Keyring::attempt()` to start a sign in from your own route, for social logins and the like.
- `Keyring::allowSignInWhen()` to keep banned or unapproved accounts out, however they try to sign in.
- Rate limits per account, per typed username and per IP address, with locks that double, a cap on failures in a row, and `limits.lock_after` to keep an account locked until its password is reset.
- Test helpers, a fake, factories, a virtual WebAuthn authenticator and a conformance suite.
- `@entity/keyring`, a browser package for WebAuthn, enrollment and the challenge page, with Vue and React bindings. Passkey sign in works with Laravel's `@laravel/passkeys` client too.
