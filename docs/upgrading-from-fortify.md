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

Keyring covers what Fortify does: login, registration, password resets, email verification, password confirmation, and two factor authentication. It takes Fortify's place in your application. Fortify keeps its two factor state in three columns on the `users` table, which allows one authenticator app per user. Keyring stores each sign-in method in its own table, so a user can have several.

Your users keep their passwords, authenticator apps, recovery codes, and `laravel/passkeys` passkeys. There are two exceptions. Bcrypt only ever stored the first 72 bytes of a password, and Keyring refuses input longer than that rather than comparing a truncated value. Users with a password over 72 bytes on a bcrypt hash will need to reset it.

The second is a password containing characters that weren't typed in Unicode's NFC form, such as an accented letter entered as a plain letter followed by a separate accent. Few keyboards produce that. Fortify hashed the password exactly as typed, but Keyring [checks the NFC form](protected-changes.md#password-rules), so the old hash no longer matches.

## Steps

1. Install Keyring and publish its files, but don't remove Fortify yet:

   ```bash
   composer require keyring/keyring
   php artisan keyring:install
   php artisan migrate
   ```

   When the `keyring:install` command asks, choose the sign-in methods your users already have: the authenticator app if you use Fortify's two factor, and passkeys if you use `laravel/passkeys`. If you used Fortify's registration, password resets, email verification, or password changes, turn those on as well. Keyring won't sign in a user who has authenticators for a method it doesn't have registered, and the `keyring:import` command won't import into one.

2. Add the `Keyring\Concerns\HasKeyring` trait to your user model. You may leave Fortify's `TwoFactorAuthenticatable` trait in place until the import is done.

3. Import your existing two factor data and passkeys. We recommend a dry run first:

   ```bash
   php artisan keyring:import fortify --dry-run
   php artisan keyring:import fortify
   ```

   The command exits with a non-zero status if any factor couldn't be imported. Sort those out before you go on. See [Importing Two Factor Data](#importing-two-factor-data).

4. Remove `laravel/fortify`, its service provider (`App\Providers\FortifyServiceProvider` in `bootstrap/providers.php`), `config/fortify.php`, and any Fortify actions you no longer need. Keyring registers routes with the same names as Fortify's, such as `login`, `logout`, `register`, and `password.request`, so the two can't stay installed together once the import is done.

5. Move your settings into `config/keyring.php` and `app/Providers/KeyringServiceProvider.php`, using the tables below as your guide.

6. Update your frontend for the new [challenge page](sign-in-flow.md#the-challenge-page) and the [authenticator routes](authenticators.md).

7. Once everything works, drop Fortify's columns in a migration of your own:

   ```php
   Schema::table('users', function (Blueprint $table) {
       $table->dropColumn(['two_factor_secret', 'two_factor_recovery_codes', 'two_factor_confirmed_at']);
   });
   ```

## Replacing Fortify in a Starter Kit

Laravel's starter kits come with Fortify already wired in. A new app built from a kit is still an upgrade, though it's one with no users to import. Follow the [steps](#steps) and skip the import. The tables below show what that looks like in a kit.

The file names come from the React starter kit, which the [example application](https://github.com/keyringphp/example) was started from. Other kits and versions differ in places, so treat these tables as a checklist.

**Remove**

| File | Why |
|---|---|
| `app/Providers/FortifyServiceProvider.php`, and its line in `bootstrap/providers.php` | `keyring:install` adds `KeyringServiceProvider` in its place. |
| `config/fortify.php` | `config/keyring.php` replaces it. |
| `app/Actions/Fortify/` and `app/Concerns/PasswordValidationRules.php` | The published `app/Actions/Keyring/` actions replace them, and they come with their own password rules. |
| `app/Http/Requests/Settings/PasswordUpdateRequest.php` and `TwoFactorAuthenticationRequest.php` | Keyring's routes validate these requests. |
| `app/Http/Requests/Settings/ProfileDeleteRequest.php` | It asked for the current password. The `keyring.fresh` middleware on the route asks for more. |
| The `add_two_factor_columns_to_users_table` and `create_passkeys_table` migrations | You can remove these only in an application with no users. If you have users, keep them until the import is done, and then [drop the columns](#steps). |
| The two factor and passkey components, and the `auth/two-factor-challenge` and `auth/confirm-password` pages | Your `challenge` and `confirm` pages, along with your settings page, replace them. |

**Change**

| File | What |
|---|---|
| `app/Models/User.php` | Swap `TwoFactorAuthenticatable`, `PasskeyAuthenticatable`, and the `PasskeyUser` interface for `HasKeyring`. Take the `two_factor_*` attributes out of the hidden list and the casts. |
| `database/factories/UserFactory.php` | Take out the `two_factor_*` attributes and the `withTwoFactor()` state. Tests use [Keyring's factories](testing.md#factories) instead. |
| `routes/settings.php` | Remove the `PUT settings/password` route. Keyring's `PUT /user/password` route has the same name, `user-password.update`. Replace the `RequirePassword` middleware on the security page with `keyring.fresh:15m`, and put the same middleware on the delete account route. |
| The profile controller and its form request | With `Features::emailChanges()` enabled, validate and save only the name. The email goes through [`POST /user/email`](protected-changes.md#changing-the-email-address). |
| The security settings controller | Pass the page everything that [Your Settings Page](quick-start.md#your-settings-page) lists. Its password form posts to Keyring's route. |
| `app/Http/Middleware/HandleInertiaRequests.php` | Share `status` and `keyring.alerts`. See [Flash Messages and Alerts](frontend.md#flash-messages-and-alerts). |
| `auth/login` | Keep the kit's passkey button and give its `@laravel/passkeys` hook [Keyring's two login routes](passkeys.md#laravels-passkeys-client). You may instead swap it for [`usePasskeyLogin()`](frontend.md#signing-in-with-a-passkey), or take it out. |
| `auth/register` and `auth/reset-password` | These pages no longer receive a `passwordRules` prop, so make the prop optional or drop it. |
| The kit's auth tests | They assert Fortify's routes and columns, so rewrite the two factor, passkey, and password confirmation tests. See [Testing](testing.md). |

The kit's pages already use the names Keyring renders, and their forms post the same fields to routes with the same names. For step-up, you may either add an `auth/confirm` page or reuse the challenge page:

```php
Keyring::page('confirm', 'auth/challenge');
```

## Importing Two Factor Data

The `php artisan keyring:import fortify` command copies three kinds of data:

- each user's `two_factor_secret` into a `totp` authenticator named "Authenticator app", which becomes their default,
- their `two_factor_recovery_codes` into a `recovery` authenticator, stored as a hash,
- every row of the `laravel/passkeys` `passkeys` table into a `passkey` authenticator, keeping its name, credential, counter, and last-used time.

There are a few things to know before you run it.

- The command reads your guard's user model. It decrypts the data with Fortify's encrypter, which is the one you set with `Fortify::encryptUsing()`. If you didn't set one, it uses Eloquent's encrypter, and then `APP_KEY`. Whichever it is, it has to be the key Fortify used to encrypt the secrets.
- A user has two factor when Fortify would challenge them. With Fortify's `confirm` option turned on, that means `two_factor_confirmed_at` is set. With the option off, which is the default for `Features::twoFactorAuthentication()` without options, a secret is enough. The command reads this setting from `config/fortify.php`. If it can't tell, because the file is gone or two factor isn't in its `features`, rows without a `two_factor_confirmed_at` value fail until you pass `--fortify-confirm=on` or `--fortify-confirm=off`.
- Every row is reported as imported, already imported, skipped, or failed. Skipped and failed rows are listed by user ID with the reason. That includes users hidden by your model's global scopes, such as soft-deleted users, so they keep their second factor if they're restored.
- Skipped rows are secrets that Fortify wasn't enforcing, which means `confirm` was on and the user never confirmed. Pass `--unconfirmed` to import them anyway.
- The command exits non-zero when anything failed. That covers a secret or recovery codes it can't decrypt or read, a passkey with no user, a credential ID that isn't base64url, and a credential that isn't a WebAuthn record. The factors for those users aren't imported. A user whose two factor data failed does get an authenticator app that can't be verified, so they're still challenged rather than signing in with only a password. The cause is usually the wrong key. Fix the key and run the command again, and the correct data replaces the placeholder. If the data is gone for good, delete that authenticator with `Authenticator::where('meta->import_failed_from', 'fortify')`, and the user enrolls again.
- The command only imports into users who have no sign-in methods in Keyring yet. Once a user has some, those methods belong to them. A later run counts the user as already imported, or skips them if they set up Keyring themselves. This means the command never brings back an authenticator app, passkey, or recovery code that a user removed.
- There is one exception. A failed two factor import's placeholder is replaced by a later run that can read the secret, whatever else the user has by then. A passkey that failed has no placeholder. If the user's two factor came across in the meantime, a later run lists that passkey as skipped. The command can't tell a row that failed from one the user removed, so the user adds the passkey again in the application.
- The command never deletes or changes Fortify's columns or the `passkeys` table, and it's safe to run more than once. Drop them once the import is clean. A user who removes every sign-in method in Keyring has none left to tell a later run they were already imported.
- Imported passkeys need `WebAuthn::passkeys()` among your [factors](factors.md), and imported codes need `Totp` and `RecoveryCodes`.
- `laravel/passkeys` accepts RS256 keys, but Keyring doesn't by default. As a result, a passkey made by Windows Hello may be imported and then refused at sign in. The command still imports it, since it may be the only sign-in method that user has, and it starts working as soon as the application accepts its algorithm. The command tells you about this: how many passkeys will be refused, the algorithm they sign with, whose they are, and what to change. Add `RS256` to [`webauthn.algorithms`](passkeys.md#rs256-and-windows-hello) to keep those passkeys working. Otherwise, those users will need to add a new passkey. The same warning covers an RSA key shorter than `webauthn.minimum_rsa_bits`. It's a warning rather than a failure, so the exit code stays zero, and a dry run shows it before anything is written.
- Imported recovery codes work as they did before. You type them as Fortify showed them, capitals included, and spaces and dashes are ignored. Keyring stores each code as a keyed hash. OWASP ASVS 5.0.0 requirement 6.5.2 allows that for a code with 112 random bits or more. Fortify's 20 letters and digits have 119 bits, but only while their case counts. The codes Keyring generates itself are case-insensitive.
- A recovery code set that holds anything other than Fortify's own codes, such as an application that swapped in a shorter format, is left behind and listed as skipped. A short code can't safely be stored that way. Those users keep their authenticator app and generate new codes.
- The `--dry-run` option reports the same outcome and exit code, without writing anything.

## How Fortify Concepts Map

### Configuration

| Fortify | Keyring |
|---|---|
| `fortify.guard` | `keyring.guard` |
| `fortify.username` | `keyring.username` |
| `fortify.lowercase_usernames` | Always on. Keyring lowercases what users type, so addresses must be stored in lowercase. If you turned this option off, lowercase your existing addresses before switching, or those users can't sign in. |
| `fortify.home` | `keyring.home` |
| `fortify.prefix`, `fortify.domain`, `fortify.middleware` | `keyring.prefix`, `keyring.domain`, `keyring.middleware` |
| `fortify.passwords` | `keyring.passwords.broker` |
| `fortify.views` | Always on. Use `Keyring::page()` to change a page. |
| `fortify.limiters` | `keyring.limits`, a factor's `limits()` method, and the `keyring` rate limiter for form routes. See [Rate Limiting](#rate-limiting). |
| `Features::registration()` | `Keyring\Features::registration()` |
| `Features::resetPasswords()` | `Keyring\Features::resetPasswords()` |
| `Features::emailVerification()` | `Keyring\Features::emailVerification()` |
| `Features::updatePasswords()` | `Keyring\Features::updatePasswords()`, which also [protects](protected-changes.md#protected-attributes) the password. |
| `Features::updateProfileInformation()` | Not included. Keep your own profile route. With `Keyring\Features::emailChanges()`, leave `email` out of it. |
| `Features::twoFactorAuthentication()` | Register `Totp` and `RecoveryCodes` in `Keyring::factors()`, turn on `Keyring\Features::manageAuthenticators()`, and choose a [policy](policies.md). |

### Actions

| Fortify | Keyring |
|---|---|
| `Fortify::createUsersUsing(CreateNewUser::class)` | `Keyring::createUsersUsing(CreateNewUser::class)`, with an action that implements `Keyring\Contracts\CreatesNewUsers`. Split your existing `create()` method in two. Its validation goes in `validate()`, without the `unique` rule on the address, because Keyring checks that itself. The rest stays in `create()`, which receives what `validate()` returned. |
| `Fortify::resetUserPasswordsUsing()` | `Keyring::resetUserPasswordsUsing()`, with an action that implements `Keyring\Contracts\ResetsUserPasswords`. Your existing `reset()` body carries over. Type the user as `Authenticatable&Model $user`, with a `@param User $user` docblock, to match the contract. |
| `Fortify::updateUserPasswordsUsing()` | `Keyring::updateUserPasswordsUsing()`, with an action that implements `Keyring\Contracts\UpdatesUserPasswords`. As above, keep the body and change the signature. Keyring checks `current_password` before your action runs, so the action's own check is no longer needed. |
| `PasswordValidationRules` trait | The published `PasswordValidationRules` trait, which is built on [Keyring's rules](protected-changes.md#password-rules). |
| `Fortify::updateUserProfileInformationUsing()` | Your own code. Email changes go through [Keyring's flow](protected-changes.md#changing-the-email-address), because `email` is protected. Your `ValidateEmailChange` action holds their validation. |
| `Fortify::authenticateUsing()` | `Keyring::findUsersUsing()` finds the user, and Keyring checks the password itself. See [Finding the User](sign-in-flow.md#finding-the-user). |
| `Fortify::confirmPasswordsUsing()` | Not needed. Step-up accepts any qualifying factor. |

### Views and Pages

| Fortify | Keyring page |
|---|---|
| `Fortify::loginView()` | `login` |
| `Fortify::registerView()` | `register` |
| `Fortify::requestPasswordResetLinkView()` | `forgot-password` |
| `Fortify::resetPasswordView()` | `reset-password` |
| `Fortify::verifyEmailView()` | `verify-email` |
| None. Fortify's verification link verifies the address when it's opened. | `email-verification`, the page the link opens |
| `Fortify::twoFactorChallengeView()` | `challenge` |
| `Fortify::confirmPasswordView()` | `confirm` |

Pass a component name or a closure to `Keyring::page()`. See [Pages](sign-in-flow.md#pages).

### Routes

| Fortify | Keyring |
|---|---|
| `POST /two-factor-challenge` | `POST /login/challenge/{factor}` |
| `POST /user/two-factor-authentication` | `POST /user/authenticators/totp` |
| `POST /user/confirmed-two-factor-authentication` | `POST /user/authenticators/totp/confirm` |
| `DELETE /user/two-factor-authentication` | `DELETE /user/authenticators/{id}` |
| `GET /user/two-factor-qr-code`, `GET /user/two-factor-secret-key` | Returned by `POST /user/authenticators/totp` (`qr`, `secret`, `url`). |
| `GET /user/two-factor-recovery-codes` | Not available. Codes are stored as hashes and are only shown when created. |
| `POST /user/two-factor-recovery-codes` | `POST /user/authenticators/recovery`, then `.../recovery/confirm`. |
| `GET` and `POST /user/confirm-password` | `GET /confirm` and `POST /confirm/{factor}` |
| `PUT /user/password` | `PUT /user/password` (same name, `user-password.update`) |
| `PUT /user/profile-information` | Not included. |

Fortify's `password.confirm` middleware keeps working, because confirming through Keyring satisfies it. Keyring's own [`keyring.fresh`](step-up.md#fresh-verification) middleware is stricter. A user who has a second factor has to confirm with it, not with the password alone.

### Responses

Fortify's response contracts map to Keyring's contracts in `Keyring\Contracts\Responses`. You swap them with `Keyring::respondWith()`:

| Fortify | Keyring |
|---|---|
| `LoginResponse`, `TwoFactorLoginResponse` | `AuthenticatedResponse` |
| `RegisterResponse` | `RegisterResponse` |
| `FailedTwoFactorLoginResponse` | `FailedResponse` |
| `LockoutResponse` | `LockoutResponse` |
| `LogoutResponse` | `LogoutResponse` |

Keyring adds `ChallengeResponse`, which is used when another factor is needed. Fortify's `PasswordResetResponse`, `SuccessfulPasswordResetLinkRequestResponse`, `PasswordUpdateResponse`, and similar contracts all map to one `StatusResponse`. Every other action returns it with a status slug, such as `reset-link-sent` or `password-updated`. See [Status Responses](sign-in-flow.md#status-responses).

### Events

| Fortify | Keyring |
|---|---|
| `TwoFactorAuthenticationEnabled`, `TwoFactorAuthenticationConfirmed` | `AuthenticatorAdded` |
| `TwoFactorAuthenticationDisabled` | `AuthenticatorRemoved` |
| `RecoveryCodesGenerated` | `RecoveryCodesGenerated` |
| `RecoveryCodeReplaced` | `RecoveryCodeUsed`. Codes aren't replaced one at a time. |
| `TwoFactorAuthenticationChallenged` | `FactorChallenged` |
| `ValidTwoFactorAuthenticationCodeProvided` | `FactorVerified` |
| `TwoFactorAuthenticationFailed` | `FactorFailed` |

All Keyring events live in `Keyring\Events`, and [Events](events.md) lists every one. Laravel's `Login`, `Logout`, `Registered`, and `Verified` events still fire. Like Fortify, Keyring also dispatches Laravel's `Failed`, `Lockout`, and `PasswordReset` events, so your existing listeners for those keep working.

### Rate Limiting

Fortify uses two named rate limiters, `login` and `two-factor`. Keyring limits every factor per account and per IP address inside the pipeline. The defaults come from `keyring.limits`, and an account that keeps failing is locked out for longer each time. See [Rate Limiting](security.md#rate-limiting). Remove your `RateLimiter::for('login', ...)` and `RateLimiter::for('two-factor', ...)` definitions.

Keyring's other form routes, such as registration, password resets, email changes, and enrollment, share one named limiter called `keyring`. It allows 6 requests a minute by default. Define `RateLimiter::for('keyring', ...)` to change that.

## Things That Behave Differently

- **Profile updates can't change the email address.** With `Features::emailChanges()` turned on, `$user->update(['email' => ...])` throws an exception. Use the [email change flow](protected-changes.md#changing-the-email-address), or `Keyring::withoutProtection()` for admin tooling.
- **Password resets don't sign users in.** They return to the login page, so their second factor still applies.
- **Password resets sign out every session.** Password changes sign out the other sessions, unless the request sends `sign_out_others: false`. Signing out also changes the "remember me" token.
- **Sessions end after two hours without activity**, whatever `session.lifetime` says, unless the browser ticked "remember me". To match a longer lifetime, change `sessions.idle`. See [Timeouts](devices-and-sessions.md#timeouts).
- **Remembered browsers sign in once more.** ["Remember me"](devices-and-sessions.md#remember-me) only brings back a session that Keyring registered. A "remember me" cookie from before the switch is refused the first time it's used.
- **Registering doesn't say when an address is taken, and it doesn't sign the new user in.** The new user is emailed a verification link and signs in once they've followed it. An address that already has an account is emailed instead of being mentioned on the form. Your `register` page needs to say "check your inbox", and your user model needs to implement `MustVerifyEmail`. To keep Fortify's behaviour, set `registration.reveal_taken`. See [Registration](sign-in-flow.md#registration).
- **The email verification link opens a page.** Fortify verifies the address when the link's `GET` request arrives. Keyring shows the `email-verification` page instead, and its button does the verifying. Add that page if you set `registration.reveal_taken`. With the default registration flow, the link sends the user to sign in instead, and signing in verifies their address. In tests, post the link's `expires` and `signature` values to its path. See [Email Verification](protected-changes.md#email-verification).
- **Adding a factor needs a fresh verification.** That means a second factor if the user has one. It also needs a verified email address if your user model implements `MustVerifyEmail`.
- **Recovery codes can't be viewed again.** They're stored as hashes, so users generate a new set instead.
- **Recovery codes come automatically** with a user's first extra factor.
- **Login errors are the same for unknown accounts and wrong passwords.** The error appears on the username field.
- **The two factor challenge has its own state.** It's a pending attempt stored in the session, not `login.id`, and it expires after `pending_logins.keep_for`.
- **Passwords follow OWASP's length rules.** That means 15 characters without a second factor and 8 with one, and breached passwords are refused. See [Password Rules](protected-changes.md#password-rules).
