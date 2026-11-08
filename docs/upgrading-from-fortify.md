# Upgrading From Fortify

- [Introduction](#introduction)
- [Steps](#steps)
- [Importing Two Factor Data](#importing-two-factor-data)
- [How Fortify Concepts Map](#how-fortify-concepts-map)
    - [Configuration](#configuration)
    - [Actions](#actions)
    - [Views and Pages](#views-and-pages)
    - [Routes](#routes)
    - [Responses](#responses)
    - [Events](#events)
    - [Rate Limiting](#rate-limiting)
- [Things That Behave Differently](#things-that-behave-differently)

## Introduction

Keyring covers what Fortify does (login, registration, password reset, email verification, password confirmation, two factor authentication) and replaces it. Fortify keeps two factor state in three columns on `users`, which gives one authenticator app per user. Keyring keeps every sign-in method in its own table, so users can have several.

Your users keep their passwords, authenticator apps, recovery codes and `laravel/passkeys` passkeys.

## Steps

1. Install Keyring and publish its files, but don't remove Fortify yet:

   ```bash
   composer require entity/keyring
   php artisan keyring:install --inertia=vue
   php artisan migrate
   ```

2. Add `Keyring\Concerns\HasKeyring` to your user model. You can leave Fortify's `TwoFactorAuthenticatable` trait in place until the import is done.

3. Import existing two factor data and passkeys. Try a dry run first:

   ```bash
   php artisan keyring:import fortify --dry-run
   php artisan keyring:import fortify
   ```

4. Remove `laravel/fortify`, its service provider (`App\Providers\FortifyServiceProvider` in `bootstrap/providers.php`), `config/fortify.php` and any Fortify actions you no longer need. Keyring registers routes with the same names as Fortify's (`login`, `logout`, `register`, `password.request` and so on), so both can't be installed at once without clashing.

5. Move your settings into `config/keyring.php` and `app/Providers/KeyringServiceProvider.php`, using the tables below.

6. Update your frontend for the new [challenge page](sign-in-flow.md#the-challenge-page) and the [authenticator routes](authenticators.md).

7. Once everything works, drop Fortify's columns in a migration of your own:

   ```php
   Schema::table('users', function (Blueprint $table) {
       $table->dropColumn(['two_factor_secret', 'two_factor_recovery_codes', 'two_factor_confirmed_at']);
   });
   ```

## Importing Two Factor Data

`php artisan keyring:import fortify` copies:

- each user's `two_factor_secret` into a `totp` authenticator named "Authenticator app", made their default,
- their `two_factor_recovery_codes` into a `recovery` authenticator, hashed,
- every row of the `laravel/passkeys` `passkeys` table into a `passkey` authenticator, keeping its name, credential, counter and last-used time.

Things to know:

- It reads your guard's user model, and needs `APP_KEY` to be the key Fortify encrypted the secrets with. Rows it can't decrypt are skipped and counted.
- Only users with `two_factor_confirmed_at` set are imported. If you never turned on Fortify's `confirm` option, that column is empty for everyone, so pass `--unconfirmed` to import every user with a secret.
- An imported authenticator app only becomes the default when the user doesn't already have one.
- It never deletes or changes Fortify's columns or the `passkeys` table, and it's safe to run more than once. Already imported authenticator apps and passkeys are skipped.
- Imported passkeys need `WebAuthn::passkeys()` among your [factors](factors.md), and imported codes need `Totp` and `RecoveryCodes`.
- Recovery codes become case-insensitive, and spaces and dashes in them are ignored.
- `--dry-run` shows the counts without writing anything.

## How Fortify Concepts Map

### Configuration

| Fortify | Keyring |
|---|---|
| `fortify.guard` | `keyring.guard` |
| `fortify.username` | `keyring.username` |
| `fortify.home` | `keyring.home` |
| `fortify.prefix`, `fortify.domain`, `fortify.middleware` | `keyring.prefix`, `keyring.domain`, `keyring.middleware` |
| `fortify.passwords` | `keyring.passwords.broker` |
| `fortify.views` | Always on. Use `Keyring::page()` to change a page. |
| `fortify.limiters` | `keyring.limits`, or a factor's `limits()`. See [Rate Limiting](#rate-limiting). |
| `Features::registration()` | `keyring.features.registration` |
| `Features::resetPasswords()` | `keyring.features.password_reset` |
| `Features::emailVerification()` | `keyring.features.email_verification` |
| `Features::updatePasswords()` | Always on: `PUT /user/password`. |
| `Features::updateProfileInformation()` | Not included. Keep your own profile route, without `email`. |
| `Features::twoFactorAuthentication()` | Register `Totp` and `RecoveryCodes` in `Keyring::factors()`, and choose a [policy](policies.md). |

### Actions

| Fortify | Keyring |
|---|---|
| `Fortify::createUsersUsing(CreateNewUser::class)` | `Keyring::createUsersUsing(CreateNewUser::class)`, with an action implementing `Keyring\Contracts\CreatesNewUsers`. Your existing action's `create()` body mostly carries over. |
| `Fortify::resetUserPasswordsUsing()` | Not needed. Keyring resets passwords itself with [its rules](protected-changes.md#password-rules). |
| `Fortify::updateUserPasswordsUsing()` | Not needed. See [Changing the Password](protected-changes.md#changing-the-password). |
| `Fortify::updateUserProfileInformationUsing()` | Your own code. Email changes go through [Keyring's flow](protected-changes.md#changing-the-email-address), because `email` is protected. |
| `Fortify::authenticateUsing()` | A [pipeline step](sign-in-flow.md#writing-a-step) for extra checks, or your own [primary factor](factors.md#optional-contracts) for a different way of finding users. |
| `Fortify::confirmPasswordsUsing()` | Not needed. Step-up accepts any qualifying factor. |

### Views and Pages

| Fortify | Keyring page |
|---|---|
| `Fortify::loginView()` | `login` |
| `Fortify::registerView()` | `register` |
| `Fortify::requestPasswordResetLinkView()` | `forgot-password` |
| `Fortify::resetPasswordView()` | `reset-password` |
| `Fortify::verifyEmailView()` | `verify-email` |
| `Fortify::twoFactorChallengeView()` | `challenge` |
| `Fortify::confirmPasswordView()` | `confirm` |

Pass a component name or closure to `Keyring::page()`. See [Pages](sign-in-flow.md#pages).

### Routes

| Fortify | Keyring |
|---|---|
| `POST /two-factor-challenge` | `POST /login/challenge/{factor}` |
| `POST /user/two-factor-authentication` | `POST /user/authenticators/totp` |
| `POST /user/confirmed-two-factor-authentication` | `POST /user/authenticators/totp/confirm` |
| `DELETE /user/two-factor-authentication` | `DELETE /user/authenticators/{id}` |
| `GET /user/two-factor-qr-code`, `GET /user/two-factor-secret-key` | Returned by `POST /user/authenticators/totp` (`qr`, `secret`, `url`). |
| `GET /user/two-factor-recovery-codes` | Not available. Codes are hashed and only shown when created. |
| `POST /user/two-factor-recovery-codes` | `POST /user/authenticators/recovery`, then `.../recovery/confirm`. |
| `GET` and `POST /user/confirm-password` | `GET /confirm` and `POST /confirm/{factor}` |
| `PUT /user/password` | `PUT /user/password` (same name, `user-password.update`) |
| `PUT /user/profile-information` | Not included. |

Fortify's `password.confirm` middleware keeps working, because confirming through Keyring satisfies it. Keyring's own [`keyring.fresh`](step-up.md#fresh-verification) is stricter: users with a second factor must use it.

### Responses

Fortify's response contracts map to Keyring's in `Keyring\Contracts\Responses`, swapped with `Keyring::respondWith()`:

| Fortify | Keyring |
|---|---|
| `LoginResponse`, `TwoFactorLoginResponse`, `RegisterResponse` | `AuthenticatedResponse` |
| `FailedTwoFactorLoginResponse` | `FailedResponse` |
| `LockoutResponse` | `LockoutResponse` |
| `LogoutResponse` | `LogoutResponse` |

Keyring adds `ChallengeResponse`, for when another factor is needed. Other actions (password reset, verification, profile) return fixed responses with a `status`.

### Events

| Fortify | Keyring |
|---|---|
| `TwoFactorAuthenticationEnabled`, `TwoFactorAuthenticationConfirmed` | `AuthenticatorAdded` |
| `TwoFactorAuthenticationDisabled` | `AuthenticatorRemoved` |
| `RecoveryCodesGenerated` | `RecoveryCodesGenerated` |
| `RecoveryCodeReplaced` | `RecoveryCodeUsed` (codes aren't replaced one by one) |
| `TwoFactorAuthenticationChallenged` | `FactorChallenged` |
| `ValidTwoFactorAuthenticationCodeProvided` | `FactorVerified` |
| `TwoFactorAuthenticationFailed` | `FactorFailed` |

All Keyring events are in `Keyring\Events`. Laravel's `Login`, `Logout`, `Registered` and `Verified` events still fire. Keyring dispatches its own `Lockout` and `PasswordReset` events, not Laravel's `Illuminate\Auth\Events\Lockout` and `Illuminate\Auth\Events\PasswordReset`, so move listeners for those.

### Rate Limiting

Fortify uses two named rate limiters, `login` and `two-factor`. Keyring limits every factor per account and per IP inside the pipeline, with `keyring.limits` as the defaults, and locks out repeated failures for longer each time. See [Rate Limiting](security.md#rate-limiting). Remove your `RateLimiter::for('login', ...)` and `RateLimiter::for('two-factor', ...)` definitions.

## Things That Behave Differently

- **Profile updates can't change the email.** `$user->update(['email' => ...])` throws. Use the [email change flow](protected-changes.md#changing-the-email-address), or `Keyring::withoutProtection()` for admin tooling.
- **Password resets don't sign users in.** They go back to the login page, so their second factor still applies.
- **Password resets sign out every session**, and password changes sign out other sessions unless the request sends `sign_out_others: false`. Signing out also changes the "remember me" token.
- **Adding a factor needs a fresh verification**, with a second factor when the user has one, and a verified email when your user model implements `MustVerifyEmail`.
- **Recovery codes can't be viewed again.** They're stored hashed. Users generate a new set instead.
- **Recovery codes come automatically** with a user's first extra factor.
- **Login errors are the same for unknown accounts and wrong passwords**, on the username field.
- **The two factor challenge has its own state.** It's a pending attempt in the session, not `login.id`, and it expires after `pending_login_ttl`.
- **Passwords follow OWASP's length rules**: 15 characters without a second factor, 8 with one, and breached passwords are refused. See [Password Rules](protected-changes.md#password-rules).
