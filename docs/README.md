# Keyring Documentation

Keyring is an authentication backend for Laravel. It handles sign in, registration, password resets, email verification, second factors, passkeys, step-up, devices, sessions and account changes. Like Fortify, it ships no UI of its own beyond optional Inertia pages you publish and own.

## Getting Started

- [Installation](installation.md): requirements, installing, the files Keyring publishes.
- [Configuration](configuration.md): every option in `config/keyring.php` and the `Keyring` facade.
- [Upgrading From Fortify](upgrading-from-fortify.md): importing existing two factor data and mapping Fortify concepts.

## Signing In

- [Factors](factors.md): the built-in factors and writing your own.
- [Policies](policies.md): deciding what each user must prove.
- [The Sign In Flow](sign-in-flow.md): login, the challenge page, the verification pipeline, responses and pages.
- [Step-Up](step-up.md): asking signed-in users to prove themselves again.
- [Passkeys & Security Keys](passkeys.md): WebAuthn settings and what Keyring does and doesn't check.

## Account Security

- [Managing Authenticators](authenticators.md): adding, renaming and removing sign-in methods, and recovery codes.
- [Devices & Sessions](devices-and-sessions.md): device recognition, the session registry and timeouts.
- [Protected Changes](protected-changes.md): changing the email address and password.
- [Risk](risk.md): risk signals and what to do about them.
- [Security Log & Emails](security-log-and-emails.md): the activity log, "was this you?" alerts and security emails.
- [Security](security.md): what Keyring guarantees, and its known limitations.

## Building Your App

- [Frontend](frontend.md): the Inertia pages and the `@entity/keyring` browser package.
- [Testing](testing.md): test helpers, fakes, factories and the conformance suite.
