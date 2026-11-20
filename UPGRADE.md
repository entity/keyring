# Upgrade Guide

This guide lists anything you need to change when updating from one release to the next.

What counts as a change you'd need to act on is in the README's [What's Stable](README.md#whats-stable). A test (`tests/Feature/PublicApiTest.php`) fails when a config default changes, or a route, middleware alias, facade method, contract, event or email type is renamed or removed, so one can't change without an entry here.

## From 0.2 to 0.3

Only apps that extend or build these classes themselves need to change anything:

- `Keyring\Login\StepUp`, `Keyring\Login\SignIn` and `Keyring\Http\Middleware\RequirePasswordChange` take a `Keyring\Login\Detours` as a new last constructor argument. Built by the container, they get it on their own. If you call `new` on one, pass `app(Detours::class)`.
- `StepUp::enrollFirst()` takes an optional `?string $continue` as its second argument. A subclass that overrides it needs that argument too.
- `PasswordController::update()` has two new injected arguments at the end, `PasswordHolds $holds` and `Detours $detours`. A subclass that overrides it needs them too.

## From 0.1 to 0.2

There's nothing to change. The new `CredentialStuffing` risk signal is off until you add it to your provider.
