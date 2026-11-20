# Upgrade Guide

This guide lists anything you need to change when updating from one release to the next.

What counts as a change you'd need to act on is in the README's [What's Stable](README.md#whats-stable). A test (`tests/Feature/PublicApiTest.php`) fails when a config default changes, or a route, middleware alias, facade method, contract, event or email type is renamed or removed, so one can't change without an entry here.

## From 0.2 to 0.3

These only matter if you extend or rebind `Keyring\Login\StepUp`, or extend Keyring's step-up middleware.

- `StepUp`'s constructor also takes a `Keyring\Devices\DeviceManager`, after the `KeyringManager`. A subclass that calls `parent::__construct()` must pass it.
- What `keyring.fresh` asks for moved from `RequireFreshVerification` to `StepUp::freshRequirement()`. The middleware's protected `requirement()` and `strongest()` methods are gone, so overriding them on a subclass of the middleware no longer has any effect. Override `freshRequirement()` or `strongest()` on `StepUp` instead.
- `RequireAssurance` and `RequireFreshVerification` now only have the `$stepUp` property. The `$assurance`, `$keyring`, and `$devices` properties are gone, and the decisions they made are `StepUp::unlessReached()` and `StepUp::unlessFresh()`.

## From 0.1 to 0.2

There's nothing to change. The new `CredentialStuffing` risk signal is off until you add it to your provider.
