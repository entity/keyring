# Upgrading From Fortify

- [Introduction](#introduction)
- [Steps](#steps)
- [Replacing Fortify in a Starter Kit](#replacing-fortify-in-a-starter-kit)
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

Your users keep their passwords, authenticator apps, recovery codes and `laravel/passkeys` passkeys. The exception is a password over 72 bytes on a bcrypt hash: bcrypt only ever stored its first 72 bytes, and Keyring refuses longer input rather than comparing a truncated value, so those users need to reset their password. The same goes for a password with characters that weren't typed in Unicode's NFC form (an accented letter sent as a letter and a separate accent, which few keyboards do): Fortify hashed it as typed and Keyring [checks the NFC form](protected-changes.md#password-rules), so it no longer matches.

## Steps

1. Install Keyring and publish its files, but don't remove Fortify yet:

   ```bash
   composer require entity/keyring
   php artisan keyring:install
   php artisan migrate
   ```

   When `keyring:install` asks, pick the sign-in methods your users already have: the authenticator app if you use Fortify's two factor, and passkeys if you use `laravel/passkeys`. Also turn on registration, password resets, email verification and password changes if you used those Fortify features. Keyring refuses to sign in a user with authenticators for a method it doesn't have registered, and `keyring:import` won't import into one.

2. Add `Keyring\Concerns\HasKeyring` to your user model. You can leave Fortify's `TwoFactorAuthenticatable` trait in place until the import is done.

3. Import existing two factor data and passkeys. Try a dry run first:

   ```bash
   php artisan keyring:import fortify --dry-run
   php artisan keyring:import fortify
   ```

   It exits non-zero if any factor couldn't be imported. Sort those out before you go on. See [Importing Two Factor Data](#importing-two-factor-data).

4. Remove `laravel/fortify`, its service provider (`App\Providers\FortifyServiceProvider` in `bootstrap/providers.php`), `config/fortify.php` and any Fortify actions you no longer need. Keyring registers routes with the same names as Fortify's (`login`, `logout`, `register`, `password.request` and so on), so both can't be installed at once without clashing.

5. Move your settings into `config/keyring.php` and `app/Providers/KeyringServiceProvider.php`, using the tables below.

6. Update your frontend for the new [challenge page](sign-in-flow.md#the-challenge-page) and the [authenticator routes](authenticators.md).

7. Once everything works, drop Fortify's columns in a migration of your own:

   ```php
   Schema::table('users', function (Blueprint $table) {
       $table->dropColumn(['two_factor_secret', 'two_factor_recovery_codes', 'two_factor_confirmed_at']);
   });
   ```

## Replacing Fortify in a Starter Kit

Laravel's starter kits come with Fortify already wired in, so a new app is an upgrade too, just one with no users to import. Follow the [steps](#steps) and skip the import. This is what they come to in a kit. The file names are from the React starter kit, which the [example app](https://github.com/entity/keyring-example) started from. Other kits and versions differ in places, so treat it as a checklist:

**Remove**

| File | Why |
|---|---|
| `app/Providers/FortifyServiceProvider.php`, and its line in `bootstrap/providers.php` | `keyring:install` adds `KeyringServiceProvider` in its place. |
| `config/fortify.php` | `config/keyring.php` replaces it. |
| `app/Actions/Fortify/` and `app/Concerns/PasswordValidationRules.php` | The published `app/Actions/Keyring/` actions replace them, with their own password rules. |
| `app/Http/Requests/Settings/PasswordUpdateRequest.php` and `TwoFactorAuthenticationRequest.php` | Keyring's routes validate these. |
| `app/Http/Requests/Settings/ProfileDeleteRequest.php` | It asked for the current password. `keyring.fresh` on the route asks for more. |
| The `add_two_factor_columns_to_users_table` and `create_passkeys_table` migrations | Only in an app with no users. With users, keep them until the import is done, then [drop the columns](#steps). |
| The two factor and passkey components, and the `auth/two-factor-challenge` and `auth/confirm-password` pages | Your `challenge` and `confirm` pages and your settings page replace them. |

**Change**

| File | What |
|---|---|
| `app/Models/User.php` | Swap `TwoFactorAuthenticatable`, `PasskeyAuthenticatable` and the `PasskeyUser` interface for `HasKeyring`. Take the `two_factor_*` attributes out of the hidden list and the casts. |
| `database/factories/UserFactory.php` | Take out the `two_factor_*` attributes and the `withTwoFactor()` state. Tests use [Keyring's factories](testing.md#factories) instead. |
| `routes/settings.php` | Remove the `PUT settings/password` route: Keyring's `PUT /user/password` has the same name, `user-password.update`. Replace the `RequirePassword` middleware on the security page with `keyring.fresh:15m`, and put it on the delete account route too. |
| The profile controller and its form request | With `Features::emailChanges()`, validate and save only the name. The email goes through [`POST /user/email`](protected-changes.md#changing-the-email-address). |
| The security settings controller | Pass the page what [Your Settings Page](quick-start.md#your-settings-page) lists. Its password form posts to Keyring's route. |
| `app/Http/Middleware/HandleInertiaRequests.php` | Share `status` and `keyring.alerts`. See [Flash Messages and Alerts](frontend.md#flash-messages-and-alerts). |
| `auth/login` | Keep the kit's passkey button and give its `@laravel/passkeys` hook [Keyring's two login routes](passkeys.md#laravels-passkeys-client), swap it for [`usePasskeyLogin()`](frontend.md#signing-in-with-a-passkey), or take it out. |
| `auth/register` and `auth/reset-password` | They no longer receive a `passwordRules` prop, so make it optional or drop it. |
| The kit's auth tests | They assert Fortify's routes and columns, so rewrite the two factor, passkey and password confirmation ones. See [Testing](testing.md). |

The kit's pages already have the names Keyring renders, and their forms post the same fields to routes with the same names. For step-up, either add an `auth/confirm` page or reuse the challenge page:

```php
Keyring::page('confirm', 'auth/challenge');
```

## Importing Two Factor Data

`php artisan keyring:import fortify` copies:

- each user's `two_factor_secret` into a `totp` authenticator named "Authenticator app", made their default,
- their `two_factor_recovery_codes` into a `recovery` authenticator, hashed,
- every row of the `laravel/passkeys` `passkeys` table into a `passkey` authenticator, keeping its name, credential, counter and last-used time.

Things to know:

- It reads your guard's user model, and decrypts with Fortify's encrypter: the one you gave `Fortify::encryptUsing()`, otherwise Eloquent's, otherwise `APP_KEY`. That has to be what Fortify encrypted the secrets with.
- A user has two factor when Fortify would challenge them. With Fortify's `confirm` option on, that takes `two_factor_confirmed_at`. With it off, the default for `Features::twoFactorAuthentication()` without options, a secret is enough. The command reads this from `config/fortify.php`. If it can't tell (the file is gone, or two factor isn't in its `features`), rows with no `two_factor_confirmed_at` fail until you pass `--fortify-confirm=on` or `--fortify-confirm=off`.
- Every row is reported as imported, already imported, skipped or failed. Skipped and failed rows are listed by user id with the reason. That includes users your model's global scopes hide, such as soft-deleted users, so they keep their second factor if they're restored.
- Skipped rows are secrets Fortify wasn't enforcing: `confirm` on and never confirmed. Pass `--unconfirmed` to import them anyway.
- The command exits non-zero when anything failed: a secret or recovery codes it can't decrypt or read, or a passkey with no user, a credential ID that isn't base64url, or a credential that isn't a WebAuthn record. Those users' factors are not imported. A user whose two factor data failed gets an authenticator app that can't be verified, so they're still challenged instead of signing in with just a password. Usually the cause is the wrong key: fix it and run the command again, and the real one replaces it. If the data is gone, delete that authenticator (`Authenticator::where('meta->import_failed_from', 'fortify')`) and the user enrolls again.
- It only imports into users with no sign-in methods in Keyring yet. Once a user has some, they're theirs: a later run counts them as already imported, or skips them if they set Keyring up themselves, so it never brings back an authenticator app, passkey or recovery code a user removed.
- One exception: a failed two factor import's stand-in is replaced by a later run that can read the secret, whatever else the user has by then. A passkey that failed has no stand-in. If the user's two factor came across in the meantime, a later run lists that passkey as skipped, since it can't tell a row that failed from one the user removed, and the user adds the passkey again in the app.
- It never deletes or changes Fortify's columns or the `passkeys` table, and it's safe to run more than once. Drop them once the import is clean: a user who removes every sign-in method in Keyring has none left to tell a later run they were already imported.
- Imported passkeys need `WebAuthn::passkeys()` among your [factors](factors.md), and imported codes need `Totp` and `RecoveryCodes`.
- `laravel/passkeys` takes RS256 keys and Keyring doesn't by default, so a passkey made by Windows Hello may be imported and then refused at sign in. Add `RS256` to [`webauthn.algorithms`](passkeys.md#rs256-and-windows-hello) to keep those working.
- Imported recovery codes work as they did: typed as Fortify showed them, capitals included. Spaces and dashes are ignored. Keyring stores each as a keyed hash, which OWASP ASVS 5.0.0 requirement 6.5.2 allows for a code with 112 random bits or more, and Fortify's 20 letters and digits have 119 only while their case counts. The codes Keyring makes itself are case-insensitive.
- A recovery code set holding anything other than Fortify's own codes (an app that swapped in a shorter format, say) is left behind and listed as skipped, since a short code can't safely be stored that way. Those users keep their authenticator app and make new codes.
- `--dry-run` reports the same outcome and exit code without writing anything.

## How Fortify Concepts Map

### Configuration

| Fortify | Keyring |
|---|---|
| `fortify.guard` | `keyring.guard` |
| `fortify.username` | `keyring.username` |
| `fortify.lowercase_usernames` | Always on. Keyring lowercases what users type, so addresses must be stored lowercased. If you turned the option off, lowercase existing addresses before switching, or those users can't sign in. |
| `fortify.home` | `keyring.home` |
| `fortify.prefix`, `fortify.domain`, `fortify.middleware` | `keyring.prefix`, `keyring.domain`, `keyring.middleware` |
| `fortify.passwords` | `keyring.passwords.broker` |
| `fortify.views` | Always on. Use `Keyring::page()` to change a page. |
| `fortify.limiters` | `keyring.limits`, a factor's `limits()`, and the `keyring` rate limiter for form routes. See [Rate Limiting](#rate-limiting). |
| `Features::registration()` | `Keyring\Features::registration()` |
| `Features::resetPasswords()` | `Keyring\Features::resetPasswords()` |
| `Features::emailVerification()` | `Keyring\Features::emailVerification()` |
| `Features::updatePasswords()` | `Keyring\Features::updatePasswords()`, which also [protects](protected-changes.md#protected-attributes) the password. |
| `Features::updateProfileInformation()` | Not included. Keep your own profile route. With `Keyring\Features::emailChanges()`, leave `email` out of it. |
| `Features::twoFactorAuthentication()` | Register `Totp` and `RecoveryCodes` in `Keyring::factors()`, turn on `Keyring\Features::manageAuthenticators()`, and choose a [policy](policies.md). |

### Actions

| Fortify | Keyring |
|---|---|
| `Fortify::createUsersUsing(CreateNewUser::class)` | `Keyring::createUsersUsing(CreateNewUser::class)`, with an action implementing `Keyring\Contracts\CreatesNewUsers`. Your existing action's `create()` body mostly carries over. |
| `Fortify::resetUserPasswordsUsing()` | `Keyring::resetUserPasswordsUsing()`, with an action implementing `Keyring\Contracts\ResetsUserPasswords`. Your existing `reset()` body carries over; type the user as `Authenticatable&Model $user` (with a `@param User $user` docblock) to match the contract. |
| `Fortify::updateUserPasswordsUsing()` | `Keyring::updateUserPasswordsUsing()`, with an action implementing `Keyring\Contracts\UpdatesUserPasswords`. Same as above: keep the body, change the signature. Keyring checks `current_password` before your action runs, so the action's own check is no longer needed. |
| `PasswordValidationRules` trait | The published `PasswordValidationRules` trait, built on [Keyring's rules](protected-changes.md#password-rules). |
| `Fortify::updateUserProfileInformationUsing()` | Your own code. Email changes go through [Keyring's flow](protected-changes.md#changing-the-email-address), because `email` is protected; your `ValidateEmailChange` action holds their validation. |
| `Fortify::authenticateUsing()` | `Keyring::findUsersUsing()` finds the user; Keyring checks the password itself. See [Finding the User](sign-in-flow.md#finding-the-user). |
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
| `LoginResponse`, `TwoFactorLoginResponse` | `AuthenticatedResponse` |
| `RegisterResponse` | `RegisterResponse` |
| `FailedTwoFactorLoginResponse` | `FailedResponse` |
| `LockoutResponse` | `LockoutResponse` |
| `LogoutResponse` | `LogoutResponse` |

Keyring adds `ChallengeResponse`, for when another factor is needed. Fortify's `PasswordResetResponse`, `SuccessfulPasswordResetLinkRequestResponse`, `PasswordUpdateResponse` and the like map to one `StatusResponse`, which every other action returns with a status slug such as `reset-link-sent` or `password-updated`. See [Status Responses](sign-in-flow.md#status-responses).

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

All Keyring events are in `Keyring\Events`, and [Events](events.md) lists every one. Laravel's `Login`, `Logout`, `Registered` and `Verified` events still fire, and like Fortify, Keyring also dispatches Laravel's `Failed`, `Lockout` and `PasswordReset`, so existing listeners for those keep working.

### Rate Limiting

Fortify uses two named rate limiters, `login` and `two-factor`. Keyring limits every factor per account and per IP inside the pipeline, with `keyring.limits` as the defaults, and locks out an account's repeated failures for longer each time. See [Rate Limiting](security.md#rate-limiting). Remove your `RateLimiter::for('login', ...)` and `RateLimiter::for('two-factor', ...)` definitions.

Keyring's other form routes (registration, password resets, email changes, enrollment) use one named limiter, `keyring`, 6 requests a minute by default. Define `RateLimiter::for('keyring', ...)` to change it.

## Things That Behave Differently

- **Profile updates can't change the email.** With `Features::emailChanges()` on, `$user->update(['email' => ...])` throws. Use the [email change flow](protected-changes.md#changing-the-email-address), or `Keyring::withoutProtection()` for admin tooling.
- **Password resets don't sign users in.** They go back to the login page, so their second factor still applies.
- **Password resets sign out every session**, and password changes sign out other sessions unless the request sends `sign_out_others: false`. Signing out also changes the "remember me" token.
- **Remembered browsers sign in once more.** ["Remember me"](devices-and-sessions.md#remember-me) only brings back a session Keyring registered, so a "remember me" cookie from before the switch is refused the first time it's used.
- **Adding a factor needs a fresh verification**, with a second factor when the user has one, and a verified email when your user model implements `MustVerifyEmail`.
- **Recovery codes can't be viewed again.** They're stored hashed. Users generate a new set instead.
- **Recovery codes come automatically** with a user's first extra factor.
- **Login errors are the same for unknown accounts and wrong passwords**, on the username field.
- **The two factor challenge has its own state.** It's a pending attempt in the session, not `login.id`, and it expires after `pending_logins.keep_for`.
- **Passwords follow OWASP's length rules**: 15 characters without a second factor, 8 with one, and breached passwords are refused. See [Password Rules](protected-changes.md#password-rules).
