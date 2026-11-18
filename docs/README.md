# Keyring Documentation

Keyring is an authentication backend for Laravel. It handles sign in, registration, password resets, email verification, second factors, passkeys, step-up, devices, sessions and account changes. It ships no UI of its own: your app owns the pages and the account actions, and Keyring supplies everything around them.

## Getting Started

- [Quick Start](quick-start.md): from installing to a working sign in, the pages to build and your settings page.
- [Installation](installation.md): requirements, installing, the files Keyring publishes.
- [Configuration](configuration.md): every option in `config/keyring.php` and the `Keyring` facade.
- [Upgrading From Fortify](upgrading-from-fortify.md): importing existing two factor data, mapping Fortify concepts and replacing Fortify in a starter kit.

## Signing In

- [Factors](factors.md): the built-in factors and writing your own.
- [Policies](policies.md): deciding what each user must prove.
- [The Sign In Flow](sign-in-flow.md): login, the challenge page, the verification pipeline, responses and pages.
- [Step-Up](step-up.md): asking signed-in users to prove themselves again.
- [Passkeys & Security Keys](passkeys.md): WebAuthn settings and what Keyring does and doesn't check.

## Account Security

- [Managing Authenticators](authenticators.md): adding, renaming and removing sign-in methods, and recovery codes.
- [Devices & Sessions](devices-and-sessions.md): device recognition, the session registry, timeouts and pruning.
- [Protected Changes](protected-changes.md): changing the email address and password.
- [Risk](risk.md): risk signals and what to do about them.
- [Security Log & Emails](security-log-and-emails.md): the activity log, "was this you?" alerts and security emails.
- [Events](events.md): every event Keyring dispatches and what it carries.
- [Security](security.md): what Keyring guarantees, where each choice comes from, and its known limitations.
- [OWASP ASVS and NIST SP 800-63B](owasp-asvs.md): where Keyring stands on every requirement of ASVS 5.0.0 that bears on it, what to turn on for each level, and what its assurance levels mean in NIST's terms.

## Building Your App

- [Frontend](frontend.md): the Inertia pages and the `@keyringjs/keyring` browser package.
- [Extending Keyring](extending.md): every option and hook in one place, and what stays fixed.
- [Recipes](recipes.md): worked examples with real packages: IP locations, Maizzle emails, SMS codes, social login and more.
- [Testing](testing.md): test helpers, fakes, factories and the conformance suite.
