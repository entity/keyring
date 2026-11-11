# OWASP ASVS

- [Introduction](#introduction)
- [What a Default Install Gives You](#what-a-default-install-gives-you)
- [Level 1](#level-1)
- [Level 2](#level-2)
- [Level 3](#level-3)
- [Requirement by Requirement](#requirement-by-requirement)
    - [V6 Authentication](#v6-authentication)
    - [V7 Session Management](#v7-session-management)
- [What Is Left to Your App](#what-is-left-to-your-app)

## Introduction

This page says what to turn on to meet the [OWASP Application Security Verification Standard 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0) in the two chapters Keyring covers: V6 Authentication and V7 Session Management. It has a setup for each of ASVS's three levels, then every requirement in both chapters with what Keyring does about it and what's left for you.

ASVS verifies an application, not a package. Keyring can meet a requirement, give you the means to, or have nothing to do with it, and the tables below say which:

| | Means |
|---|---|
| **Met** | Keyring does it whatever you configure. |
| **Met by default** | Keyring does it as installed. The row says which option or edit would undo it. |
| **Needs setup** | Keyring can do it once you turn something on. The row says what. |
| **Partly** | Keyring covers some of it. The row says what's missing and what to do instead. |
| **Yours** | It's about your pages, your process or your infrastructure. |
| **Not met** | Keyring doesn't do it and has no option for it. |
| **N/A** | Keyring has nothing the requirement applies to. |

Each level includes the ones below it. The other ASVS chapters (TLS, input validation, access control, your own pages' headers and so on) are your app's throughout.

## What a Default Install Gives You

`php artisan keyring:install` with every default accepted, or with `--no-interaction`, sets up:

- the password as the only sign-in method, with [Keyring's password rules](protected-changes.md#password-rules),
- `Features::registration()`, `resetPasswords()`, `emailVerification()` and `updatePasswords()`,
- [registration that doesn't reveal who has an account](sign-in-flow.md#without-revealing-who-has-an-account),
- the emails that tell users their password, sign-in methods, recovery codes or email address changed, that a recovery code was used, or that their account was locked,
- rate limits, the timebox, the session registry and a 30 day limit on every session.

That covers Level 1, apart from what your own pages have to do. Nothing in it asks for a second factor, because there isn't one to set up: pick one when installing and the installer's next question, "Require a second factor for everyone?", defaults to yes.

## Level 1

Start from the default install, then:

1. Keep a server-side session driver (`SESSION_DRIVER=database`, Laravel's default, or `redis` or `file`). The `cookie` driver can't destroy an old session ([7.2.4](#v72-fundamental-session-management-security)).
2. Keep the rate limiter's cache store (`cache.limiter`, or your default) somewhere that holds its keys between requests and that your deploys don't clear: the limits, the locks and sent codes all live there ([6.3.1](#v63-general-authentication-security)).
3. Build your forms so passwords are masked and can be pasted and filled by a password manager ([6.2.6, 6.2.7](#v62-password-security)).
4. Give users a form that posts to `PUT /user/password` ([6.2.2](#v62-password-security)).
5. Put a sign-out button on every signed-in page, though ASVS only asks for it from Level 2.

Don't turn on `registration.reveal_taken`, add composition rules to the password, or remove a [mandatory pipeline step](sign-in-flow.md#mandatory-steps).

## Level 2

Everything in Level 1, and:

1. **Require a second factor.** Install with an authenticator app, passkeys or security keys and answer yes to "Require a second factor for everyone?", or set it up yourself ([Requiring a Second Factor](policies.md#requiring-a-second-factor)):

    ```php
    // app/Providers/KeyringServiceProvider.php
    Keyring::factors([
        Password::class,
        Totp::class,
        RecoveryCodes::class,
        WebAuthn::passkeys(),
    ]);

    Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());

    $this->app->make(Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');
    ```

    ```php
    // config/keyring.php
    'features' => [
        Features::registration(),
        Features::resetPasswords(),
        Features::emailVerification(),
        Features::updatePasswords(),
        Features::manageAuthenticators(),
        Features::devices(),
    ],

    'enrollment_url' => '/settings/security',
    ```

2. **Hash with argon2id**, so a 64 character password in any script is accepted ([6.2.9](#v62-password-security)). The [conformance suite](testing.md#the-conformance-suite) fails on bcrypt until you do, or say you're keeping it:

    ```ini
    HASH_DRIVER=argon2id
    ```

3. **Set an inactivity timeout** ([7.3.1](#v73-session-timeout)). Keyring ships without one:

    ```php
    'sessions' => [
        'idle' => '30m',
    ],
    ```

4. **Accept authenticator app codes for 30 seconds only** ([6.5.5](#v65-general-multi-factor-authentication-requirements)). In `Keyring::factors()`, in place of `Totp::class`:

    ```php
    fn ($app) => $app->make(Totp::class, ['window' => 0]),
    ```

5. **Turn on `Features::devices()`**, so users can see where they're signed in and sign out elsewhere ([7.4.3, 7.5.2](#v75-defenses-against-session-abuse)), and offer "sign out everywhere else" after a sign-in method is added or removed.
6. **Write down** your list of words a password must not be made up of and put it in `passwords.context` ([6.1.2, 6.2.11](#v62-password-security)), your session timeouts and why you chose them ([7.1.1](#v71-session-management-documentation)), and that an account may have any number of sessions ([7.1.2](#v71-session-management-documentation)).
7. **Give administrators a way to end a user's sessions** ([7.4.5](#v74-session-termination)), and a process for someone who has lost their second factor and their recovery codes ([6.4.4](#v64-authentication-factor-lifecycle-and-recovery)).

Email codes meet Keyring's `aal2` at sign in but not NIST's, and Level 3 rules them out. Leave `EmailCode::asSecondFactor()` out unless you need it.

## Level 3

Everything in Level 2, and:

1. **Require a hardware key that proves what it is.** Register security keys with attestation, list the manufacturers' root certificates you accept, and require AAL3 at sign in and for enrollment:

    ```php
    // app/Providers/KeyringServiceProvider.php
    Keyring::factors([
        Password::class,
        WebAuthn::securityKeys()->requireAttestation(),
    ]);

    Keyring::require(Requirement::aal3()->ifEnrolled());

    $this->app->make(Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled:aal3');
    ```

    ```php
    // config/keyring.php
    'webauthn' => [
        'attestation_roots' => [storage_path('attestation/yubico-root.pem')],
    ],
    ```

    With `ifEnrolled()` a new user signs in with their password, and `keyring.enrolled:aal3` keeps them on your enrollment page until they've added a key; from then on they need it every time. Drop `ifEnrolled()` if you hand out keys before an account first signs in. See [Requiring Attestation](passkeys.md#requiring-attestation). Without attestation, "hardware" is only what the key says about itself.

2. **No email codes, and no SMS** ([6.3.6](#v63-general-authentication-security), [6.6.1](#v66-out-of-band-authentication-mechanisms)). Don't register `EmailCode::asSecondFactor()` or an SMS factor of your own. Recovery codes can't meet `aal3` either, so a lost key goes to your support process.
3. **Tell users about suspicious sign ins** ([6.3.5](#v63-general-authentication-security)). Register the notices the installer leaves commented out, turn on the security log, and pick [risk signals](risk.md) with a response that notifies, as [Telling the User](risk.md#telling-the-user) shows for a sign in after a long quiet period or after several failures:

    ```php
    Keyring::notifications([
        'new_device' => Notifications\NewDevice::class,
        'second_factor_failed' => Notifications\SecondFactorFailed::class,
        'suspicious_activity' => Notifications\SuspiciousActivity::class,
        'clone_suspected' => Notifications\CloneSuspected::class,
        'email_change_reverted' => Notifications\EmailChangeReverted::class,
    ]);
    ```

4. **Keep the default registration** ([6.3.8](#v63-general-authentication-security)): `registration.reveal_taken` stays `false`.
5. **Ask again before your most sensitive operations** ([7.5.3](#v75-defenses-against-session-abuse)): `keyring:aal3` or `keyring.fresh:5m` on those routes. AAL3 lapses after 15 minutes idle or 12 hours.
6. **Shorten the inactivity timeout** to what your risk analysis says, 15 minutes being NIST's figure for AAL3.
7. **Restrict who can write** to `keyring_authenticators` and to your attestation root files ([6.7.1](#v67-cryptographic-authentication-mechanism)).

## Requirement by Requirement

### V6 Authentication

#### V6.1 Authentication Documentation

| | Level | | What to do |
|---|---|---|---|
| 6.1.1 Rate limiting and lockout are documented | 1 | Met | Keyring's are in [Rate Limiting](security.md#rate-limiting), with how they avoid locking the owner out. Your own security documentation can point there; write down any limit you change. |
| 6.1.2 A documented list of context-specific words | 2 | Yours | Write the list: the names of your organisation, products, systems, projects and teams. It goes in `passwords.context`, and [Context-Specific Words](protected-changes.md#context-specific-words) documents what Keyring adds to it. |
| 6.1.3 Every authentication pathway is documented | 2 | Met | Keyring's are in [The Sign In Flow](sign-in-flow.md). Add your own: a social login, or anywhere you call `Auth::login()`. |

#### V6.2 Password Security

| | Level | | What to do |
|---|---|---|---|
| 6.2.1 At least 8 characters | 1 | Met by default | 15 without a second factor, 8 with one, and Keyring throws on a configured minimum under 8. Keep `PasswordRules::for()` in your published actions. |
| 6.2.2 Users can change their password | 1 | Met by default | `Features::updatePasswords()` is on in a default install. Build the form that posts to [`PUT /user/password`](protected-changes.md#changing-the-password). |
| 6.2.3 A change needs the current and the new password | 1 | Met | Keyring checks `current_password` itself, whatever your action does. A user with no password, who signs in with a passkey alone, sets one with a fresh verification. |
| 6.2.4 Checked against at least the top 3,000 passwords | 1 | Met by default | The bundled list holds the 10,000 most common passwords of 8 characters or more and the 3,000 most common of 15 or more, and runs in every environment. Keep `PasswordRules::for()` in your published actions. |
| 6.2.5 No composition rules | 1 | Met by default | Don't add `mixedCase()`, `numbers()` or `symbols()` through the rules' `$adjust` callback. A longer minimum is fine. |
| 6.2.6 Password fields are masked | 1 | Yours | Use `type="password"` on your forms. A "show" toggle is allowed. |
| 6.2.7 Paste and password managers are permitted | 1 | Yours | Don't block paste, and set `autocomplete="current-password"` or `"new-password"`. Keyring's browser package touches neither. |
| 6.2.8 The password is verified exactly as typed | 1 | Met | |
| 6.2.9 Passwords of at least 64 characters are permitted | 2 | Needs setup | Set `HASH_DRIVER=argon2id`. With bcrypt, Laravel's default, Keyring refuses anything over 72 bytes rather than cut it short, which turns away 64 characters of accented or non-Latin text. The conformance suite flags bcrypt. |
| 6.2.10 No periodic rotation | 2 | Met | Keyring has no password expiry. Don't add one. |
| 6.2.11 The context word list is enforced | 2 | Needs setup | Put your list (6.1.2) in `passwords.context`. Keyring refuses a password made up of nothing but listed words, the app's name, the user's name, the name part of their email address and their organisation's part of its domain, with digits and punctuation taken out and look-alike spellings such as `k3yr1ng` read as letters. A longer passphrase that only has one of them in it passes. |
| 6.2.12 Checked against breached passwords | 2 | Met by default | In production, through Have I Been Pwned. `passwords.uncompromised => false` turns it off, and `true` runs it everywhere. Laravel's check lets a password through when the service can't be reached: set `passwords.refuse_unchecked` to refuse it instead. |

#### V6.3 General Authentication Security

| | Level | | What to do |
|---|---|---|---|
| 6.3.1 Credential stuffing and brute force controls | 1 | Met by default | Per account, per typed username, per IP address and in a row, all inside the timebox. Keep the `limits` options near their defaults, and keep the limiter's cache store somewhere that holds its keys and that your deploys don't clear. See [Rate Limiting](security.md#rate-limiting). |
| 6.3.2 No default accounts | 1 | Met | Keyring creates no users. Don't seed any in production. |
| 6.3.3 Multi-factor authentication is required; a hardware factor at Level 3 | 2 | Needs setup | Level 2: a second factor registered and `keyring.enrolled`, which the installer sets up when you answer yes to requiring one. Level 3: `Requirement::aal3()`, `keyring.enrolled:aal3` and `requireAttestation()`. See [Level 2](#level-2) and [Level 3](#level-3). Until a user enrolls they are signed in, and held at your enrollment page. |
| 6.3.4 No undocumented pathways, and consistent strength across them | 2 | Met | Every sign in runs one pipeline. Start a social login with [`Keyring::attempt()`](sign-in-flow.md#starting-a-sign-in-yourself) rather than `Auth::login()`, which registers a session at no assurance level. |
| 6.3.5 Users are notified of suspicious authentication attempts | 3 | Needs setup | Register the `new_device`, `second_factor_failed`, `suspicious_activity` and `clone_suspected` notices, turn on `Features::devices()` and `Features::securityLog()`, and pick [risk signals](risk.md), among them `InactiveAccount` and `SuccessAfterFailures`, with a response that notifies ([Telling the User](risk.md#telling-the-user)). `account_locked`, which a default install registers, is only sent with `limits.lock_after`; an ordinary lockout that lifts by itself emails nobody, so listen for `Lockout` if you want to. |
| 6.3.6 Email isn't an authentication factor | 3 | Met by default | Don't register `EmailCode::asSecondFactor()`. |
| 6.3.7 Users are notified when authentication details change | 3 | Met by default | A default install mails a changed or reset password, a sign-in method added or removed, new recovery codes, a recovery code used and a changed email address. Also register `email_change_reverted`. Renaming a sign-in method or changing the default one sends nothing. Each kind is capped at five an hour per account, with every event still in the security log. Installing with `--no-emails` turns them off. |
| 6.3.8 Valid users can't be deduced from sign in, registration or forgot password | 3 | Met by default | All three answer the same for every address, in the same time. Keep `registration.reveal_taken` off. A username of your own that must be unique will still say when it's taken. See [Registration](sign-in-flow.md#without-revealing-who-has-an-account). |

#### V6.4 Authentication Factor Lifecycle and Recovery

| | Level | | What to do |
|---|---|---|---|
| 6.4.1 Initial passwords and activation codes are random and short-lived | 1 | Met | Keyring never generates a password. Its links and codes are random and expire. Don't email users a password of your own making. |
| 6.4.2 No password hints or secret questions | 1 | Met | Don't add any. |
| 6.4.3 Password reset doesn't bypass multi-factor authentication | 2 | Met | A reset signs nobody in, and leaves second factors and their limits alone. |
| 6.4.4 A lost factor is recovered with identity proofing | 2 | Yours | Recovery codes are Keyring's only way back in. For someone who has lost those too, your support process decides what they must prove before an administrator removes their authenticators. |
| 6.4.5 Renewal reminders for factors that expire | 3 | N/A | Nothing Keyring issues expires. |
| 6.4.6 Administrators can start a reset but not choose the password | 3 | Yours | In your admin tool, send a reset link with `Password::broker()->sendResetLink(['email' => $user->email])`. Don't set a user's password with `Keyring::withoutProtection()`. |

#### V6.5 General Multi-Factor Authentication Requirements

| | Level | | What to do |
|---|---|---|---|
| 6.5.1 Codes work once | 2 | Met | On any session driver. A sent code's state is kept in the rate limiter's cache store, which has to hold its keys between requests. |
| 6.5.2 Lookup secrets under 112 bits are stored salted and hashed | 2 | Met | Recovery codes are stored as a keyed hash, which the requirement allows from 112 bits. Keyring's own carry 120, those imported from Fortify 119, and nothing shorter is stored or accepted. |
| 6.5.3 Secrets come from a secure random generator | 2 | Met | |
| 6.5.4 Codes have at least 20 bits of entropy | 2 | Met | Emailed codes are eight digits, and a code factor set to fewer than six is refused. |
| 6.5.5 Out-of-band codes last 10 minutes at most, authenticator app codes 30 seconds | 2 | Needs setup | Sent codes last 10 minutes, and a longer life is refused. Authenticator app codes are accepted for up to about 90 seconds by default, which [doesn't meet the requirement](factors.md#authenticator-apps-totp): register `Totp` with `window` set to `0` ([Level 2](#level-2)). |
| 6.5.6 Any factor can be revoked | 3 | Needs setup | `Features::manageAuthenticators()` lets users remove a sign-in method, and `Features::devices()` a device. |
| 6.5.7 Biometrics only as a secondary factor | 3 | Met | A key's user verification only counts together with possession of the key. |
| 6.5.8 Authenticator app codes use the server's time | 3 | Met | |

#### V6.6 Out-of-Band Authentication Mechanisms

| | Level | | What to do |
|---|---|---|---|
| 6.6.1 Phone and SMS codes are restricted, and absent at Level 3 | 2 | Yours | Keyring ships no SMS factor. If you [build one](recipes.md#sms-codes), offer an authenticator app or passkeys beside it and tell users it's the weaker choice. Don't register it at Level 3. |
| 6.6.2 A code is bound to the request it was made for | 2 | Met | |
| 6.6.3 Codes are protected from brute force | 2 | Met | Five wrong guesses per sign in, on top of the usual limits. |
| 6.6.4 Push notifications are rate limited | 3 | N/A | Keyring has no push factor. |

#### V6.7 Cryptographic Authentication Mechanism

| | Level | | What to do |
|---|---|---|---|
| 6.7.1 Keys used to verify assertions are protected from modification | 3 | Yours | No Keyring route writes a stored public key. Restrict who can write to the `keyring_authenticators` table and to the files in `webauthn.attestation_roots`. |
| 6.7.2 Challenges are at least 64 bits and unique | 3 | Met | |

#### V6.8 Authentication with an Identity Provider

| | Level | | What to do |
|---|---|---|---|
| 6.8.1 An identity can't be spoofed through another provider | 2 | Yours | In your factor, find users by the provider and the provider's ID together, never by email address. See [Social Login](recipes.md#social-login-with-socialite). |
| 6.8.2 Signatures on assertions are validated | 2 | Yours | That's the library you use for the provider. Keyring never sees an assertion. |
| 6.8.3 SAML assertions are used once | 2 | N/A | Keyring doesn't process SAML. |
| 6.8.4 Authentication strength claimed by the provider is verified | 2 | Yours | The recipe counts a social login as one factor whatever the provider did, and Keyring then asks for the user's own second factor. To rely on the provider's `acr`, `amr` or `auth_time` instead, check them in your factor. |

### V7 Session Management

#### V7.1 Session Management Documentation

| | Level | | What to do |
|---|---|---|---|
| 7.1.1 Timeouts are documented and justified | 2 | Yours | Write down the values you chose and why. Keyring's defaults and where they come from are in [Timeouts](devices-and-sessions.md#timeouts): no inactivity limit of its own, 30 days overall, and each assurance level lapsing on NIST SP 800-63B's clock. Say so if "remember me" is allowed to outlast your inactivity limit. |
| 7.1.2 The number of concurrent sessions and what happens at the limit is documented | 2 | Not met | Keyring doesn't limit how many sessions an account has, and has no option to. Document that the number is unlimited and that users can list and end them (7.5.2). |
| 7.1.3 Federated session lifetimes are documented | 2 | Yours | Keyring's session carries on after an identity provider's ends, and there's no single logout. Document how yours relate. |

#### V7.2 Fundamental Session Management Security

| | Level | | What to do |
|---|---|---|---|
| 7.2.1 Session tokens are verified on the backend | 1 | Met | On every `web` request. Add `keyring.session` to any other route group users are signed in on. |
| 7.2.2 Tokens are generated dynamically | 1 | Met | |
| 7.2.3 Tokens are random with at least 128 bits | 1 | Met | |
| 7.2.4 A new token on authentication, and the old one ended | 1 | Met by default | With a server-side session driver. Laravel's `cookie` driver has nothing on the server to destroy, so a copied cookie keeps working after a step-up. |

#### V7.3 Session Timeout

| | Level | | What to do |
|---|---|---|---|
| 7.3.1 An inactivity timeout | 2 | Needs setup | Set `sessions.idle`. With `null`, the default, inactivity is left to Laravel's `session.lifetime`, and a browser that ticked "remember me" has no inactivity timeout at all inside the overall limit. Routes behind `keyring:aal2` or `keyring.fresh` ask again either way. |
| 7.3.2 An absolute maximum lifetime | 2 | Met by default | `sessions.absolute`, 30 days. Choose the length from your risk analysis; it can't be turned off. Keep `sessions.middleware` on. |

#### V7.4 Session Termination

| | Level | | What to do |
|---|---|---|---|
| 7.4.1 A terminated session can't be used again | 1 | Met by default | Keep `sessions.middleware` on, and add `keyring.session` to signed-in route groups outside `web`. |
| 7.4.2 Sessions end when an account is disabled or deleted | 1 | Met | Deleting a user revokes their sessions. To disable one, use [`Keyring::allowSignInWhen()`](sign-in-flow.md#who-may-sign-in), not a global scope. |
| 7.4.3 The option to end other sessions after a factor changes | 2 | Partly | A password change offers it (`sign_out_others`, on by default), and a reset and an applied email change do it. Adding or removing a sign-in method ends no other session: turn on `Features::devices()` and offer "sign out everywhere else" (`DELETE /user/devices`) on your settings page. |
| 7.4.4 Sign out is easy to find on every signed-in page | 2 | Yours | Put a button that posts to `/logout` in your layout. |
| 7.4.5 Administrators can end a user's sessions, or everyone's | 2 | Partly | For one user, call `app(Sessions::class)->signOutEverywhere($user)` from your admin tool. Keyring has no call for every user at once: run that over your users. |

#### V7.5 Defenses Against Session Abuse

| | Level | | What to do |
|---|---|---|---|
| 7.5.1 Re-authentication before changing sign-in details | 2 | Met by default | `changes_middleware` is `keyring.fresh:15m`. Don't empty it. For an attribute of your own that affects recovery (a phone number), put `keyring.fresh` on the route that changes it. |
| 7.5.2 Users can see and end their sessions | 2 | Needs setup | `Features::devices()` adds the list and the routes to end one device or all others, behind a fresh verification. It lists devices, each with its sessions: a session your own `Auth::login()` started from a browser Keyring hasn't seen isn't listed, and "sign out everywhere else" ends it. |
| 7.5.3 Further authentication before highly sensitive operations | 3 | Yours | Put `keyring.fresh:5m`, `keyring:aal2` or `keyring:aal3` on those routes. See [Step-Up](step-up.md). |

#### V7.6 Federated Re-authentication

| | Level | | What to do |
|---|---|---|---|
| 7.6.1 Session lifetime between your app and an identity provider behaves as documented | 2 | Yours | Keyring reads nothing from the provider after sign in. If the provider's limits must be honoured, your factor has to arrange it. |
| 7.6.2 A session is only created by the user's action | 2 | Yours | Keyring's own sessions start on a POST that carries a proof. For a social login, the redirect and consent are the provider's and your callback's. |

## What Is Left to Your App

Whatever level you aim for, these are outside what a package can do:

- **TLS everywhere**, with `SESSION_SECURE_COOKIE=true` and trusted proxies configured, so rate limits see real addresses.
- **Your pages.** Keyring ships none: masked password fields, paste and password managers left alone, a visible sign-out button, and telling users the risks of a weaker factor are in your templates.
- **Headers on your own pages.** Keyring's responses send `Cache-Control: no-store` and `Referrer-Policy: same-origin`. A content security policy and the rest are yours, for every page.
- **Your mail provider.** Verification links, reset links and security notices are only as private and as prompt as the mail that carries them. Its bounce and delivery reports sit outside the request, where Keyring can't make two answers look alike.
- **Your session and cache stores.** A server-side session driver, and a rate limiter store that doesn't lose its keys: limits, locks and sent codes are kept there.
- **Your documentation.** ASVS asks for your password word list, your session timeouts and your sign-in pathways in writing.
- **Your administrators.** Who may end sessions, send reset links or remove a lost authenticator, and what a user must prove first.
- **Identity providers.** Everything about a federated sign in beyond starting Keyring's session.
