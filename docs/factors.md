# Factors

- [Introduction](#introduction)
- [Registering Factors](#registering-factors)
- [Built-in Factors](#built-in-factors)
    - [Password](#password)
    - [Authenticator Apps (TOTP)](#authenticator-apps-totp)
    - [Email Codes](#email-codes)
    - [Recovery Codes](#recovery-codes)
    - [Passkeys and Security Keys](#passkeys-and-security-keys)
- [Categories](#categories)
- [Writing a Code Factor](#writing-a-code-factor)
- [Writing Any Other Factor](#writing-any-other-factor)
- [Showing a Factor in the Frontend](#showing-a-factor-in-the-frontend)
- [Using Your Own Authenticator Model](#using-your-own-authenticator-model)

## Introduction

A **factor** is a way of proving who you are: a password, an authenticator app, a passkey. Every factor implements the same `Keyring\Contracts\Factor` contract, so adding one never needs new routes, controllers or tables.

An **authenticator** is one user's instance of a factor: the authenticator app on their phone, the security key on their keychain, their set of recovery codes. Authenticators are `Keyring\Models\Authenticator` rows in `keyring_authenticators`. A user can have as many as the factor allows. Factors that keep their state elsewhere, like the password on the `users` table, appear as unsaved "virtual" authenticators.

Each factor has a **key** such as `totp` or `passkey`. The key is used in URLs (`/login/challenge/totp`), in the `factor` column, and in the frontend's component map. Keys must match `[a-z0-9-]+`, and `challenge` is reserved.

## Registering Factors

Register factors in the `boot()` method of your `KeyringServiceProvider`:

```php
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;

Keyring::factors([
    Password::class,
    WebAuthn::passkeys(),
    WebAuthn::securityKeys(),
    Totp::class,
    EmailCode::class,
    RecoveryCodes::class,
]);
```

The list accepts class names (resolved from the container), instances, and closures that receive the container:

```php
Keyring::factors([
    Password::class,
    fn ($app) => $app->make(Totp::class, ['window' => 2]),
    new RecoveryCodes(count: 10),
]);
```

`Keyring::extend()` adds a factor without replacing the list, which is handy in a package:

```php
Keyring::extend('sms', fn ($app) => $app->make(SmsCode::class));
```

The factor is registered under the first argument, and its `key()` must return the same value, or Keyring throws an `InvalidArgumentException` when it resolves the factors.

If you never call `Keyring::factors()`, Keyring uses `Password`, `Totp` and `RecoveryCodes`.

Removing a factor from the list doesn't delete anyone's authenticators. Keyring ignores rows whose factor isn't registered: they stop counting towards the policy and aren't offered at sign in. Code that calls `$authenticator->factor()` on such a row throws `Keyring\Exceptions\UnknownFactor`, so delete or migrate those rows if you drop a factor for good. `UnknownFactor` is an HTTP exception, so an unregistered factor key in a URL gives a `404`.

## Built-in Factors

| Key | Class | Categories | Starts a login | Users add it | Priority |
|---|---|---|---|---|---|
| `password` | `Password` | knowledge | yes | no | 40 |
| `totp` | `Totp` | possession | no | yes | 60 |
| `email-code` | `EmailCode` | possession | no | yes, one | 30 |
| `recovery` | `RecoveryCodes` | possession | no | yes, one set | 0 |
| `passkey` | `WebAuthn::passkeys()` | possession, plus inherence when the user was verified | yes | yes | 100 |
| `security-key` | `WebAuthn::securityKeys()` | possession, plus inherence when the user was verified | no | yes | 90 |

When Keyring needs another factor, it offers the user's default authenticator first, then the rest by priority.

### Password

The password stays in your `users` table, so password resets and Laravel's own helpers keep working. A user without a password doesn't have this authenticator. It can't be added or removed through Keyring's authenticator routes; it changes through the [password change](protected-changes.md#changing-the-password) and [reset](protected-changes.md#resetting-the-password) flows.

When a login starts with an unknown address, Keyring still runs a password hash, so the response takes the same time either way. A correct password is rehashed if your hashing settings changed.

### Authenticator Apps (TOTP)

Time-based one-time passwords (RFC 6238). Enrolling returns a 32 character secret, an `otpauth://` URL and an SVG QR code. Codes are accepted one time step either side of now by default (the `window` constructor argument).

Each authenticator remembers the last time step it accepted, under a row lock, so a code can't be used twice, even by two requests at the same moment.

A user can have several authenticator apps.

### Email Codes

An eight digit code sent to the user's current email address. A code:

- is only sent when the user asks (see [Sending Codes](sign-in-flow.md#sending-codes)), never just by opening the challenge page,
- expires after 10 minutes,
- allows five wrong guesses, then stops working,
- is replaced by any newer code,
- is stored as a keyed hash, never in plain text.

Enrolling sends a code to the current address, and the user types it to confirm. Every copy would go to the same address, so a user has at most one: enrolling again replaces it. Email codes are only as strong as the inbox, so they aren't phishing resistant.

### Recovery Codes

Eight single-use codes in the form `xxxxx-xxxxx`, shown once. They're stored as keyed hashes. Typing them is case-insensitive, and spaces and dashes are ignored. Like TOTP, each code is used up under a row lock.

A user has at most one set. Generating a new set replaces the old one. Users get a set automatically with their first extra factor. Recovery codes are a fallback, so they can never be the default authenticator. See [Recovery Codes](authenticators.md#recovery-codes).

The factor's key is available as `RecoveryCodes::KEY` (`recovery`), for code that looks the set up.

The hashes are keyed with `APP_KEY`. When you rotate it, put the old key in `APP_PREVIOUS_KEYS` and existing codes keep working.

Once every code is used, the set no longer counts as a factor, so policies and step-up stop asking for it.

### Passkeys and Security Keys

One WebAuthn driver with two profiles. Passkeys are discoverable and always verify the user, so they can sign in on their own. Security keys are a second factor. See [Passkeys & Security Keys](passkeys.md).

## Categories

Every verification proves one or more **categories**, from `Keyring\Enums\Category`:

- `Knowledge`: something the user knows, like a password.
- `Possession`: something they have, like a phone, a key or saved recovery codes.
- `Inherence`: something they are, like a fingerprint checked by their authenticator.

Policies count distinct categories, not verifications, so a password and a PIN together are still one factor. See [Policies](policies.md).

A factor declares the categories it expects in `categories()`, which Keyring uses to plan what to offer. The categories that count are the ones in the `Verification` returned by `verify()`. That's how a security key only counts as inherence when it actually verified the user that time.

## Writing a Code Factor

Factors that send a one-time code extend `Keyring\Factors\CodeFactor`. It implements sending, checking, expiry, guess limits, resending and enrollment. A code only verifies the authenticator it was sent to, so a user with two phones can't send to one and type the code against the other. You provide a key, a default name and the delivery:

```php
namespace App\Keyring;

use App\Notifications\SmsCode as SmsCodeNotification;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Keyring\Factors\CodeFactor;
use Keyring\Models\Authenticator;

class SmsCode extends CodeFactor
{
    protected int $length = 6;

    protected int $ttl = 300;

    public function key(): string
    {
        return 'sms';
    }

    protected function defaultName(Authenticatable&Model $user): string
    {
        return 'Text message';
    }

    protected function deliver(Authenticatable&Model $user, Authenticator $authenticator, string $code): void
    {
        $user->notify(new SmsCodeNotification($authenticator->secret, $code));
    }
}
```

Then add it to your factors:

```php
Keyring::factors([..., SmsCode::class]);
```

You can override these properties:

| Property | Default | Means |
|---|---|---|
| `$length` | `8` | Digits per code. |
| `$ttl` | `600` | Seconds a code stays valid. |
| `$maxGuesses` | `5` | Wrong guesses allowed per code. |

Code factors count as possession and have priority 30. Override `categories()`, `priority()` or `present()` to change that.

### Collecting Details at Enrollment

To collect something like a phone number when the user adds the factor, override `newAuthenticator()`. It receives the request that begins enrollment and returns an unsaved authenticator. Whatever you put in `secret` (encrypted at rest) or `meta` is carried through the enrollment and saved when it's confirmed. Keyring doesn't validate the begin request for you, so validate it here:

```php
use Illuminate\Http\Request;

protected function newAuthenticator(Authenticatable&Model $user, Request $request): Authenticator
{
    $phone = $request->validate(['phone' => ['required', 'string', 'max:32']])['phone'];

    return $this->makeAuthenticator([
        'name' => $this->nameFrom($request, $this->defaultName($user)),
        'secret' => $phone,
    ])->setRelation('authenticatable', $user);
}
```

`deliver()` then reads the number from `$authenticator->secret`.

Codes go to the address on the authenticator, so confirming the enrollment proves the user can receive them.

## Writing Any Other Factor

Anything else implements `Keyring\Contracts\Factor`. Extending `Keyring\Factors\Factor` gives you defaults for everything except `key()`, `categories()` and `verify()`.

```php
namespace App\Keyring;

use Illuminate\Http\Request;
use Keyring\Enums\Category;
use Keyring\Factors\Factor;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

class HardwareToken extends Factor
{
    public function key(): string
    {
        return 'hardware-token';
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Possession];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $valid = $this->consume($authenticator, function (Authenticator $locked) use ($request) {
            // Check $request->input('code') against $locked, and record that
            // it was used (for example in $locked->withMeta(...)).
            return app(TokenServer::class)->check($locked->secret, (string) $request->input('code'));
        });

        return $valid ? $this->verified($authenticator) : null;
    }
}
```

The contract's methods:

| Method | Default in `Factor` | Purpose |
|---|---|---|
| `key()` | none | The factor's key. |
| `categories($authenticator)` | none | The categories it's expected to prove. |
| `verify($attempt, $authenticator, $request)` | none | Check the proof. Return a `Verification`, or `null` when it's wrong. |
| `phishingResistant($authenticator)` | `false` | Whether the proof is bound to your origin. Only WebAuthn should say yes. |
| `priority()` | `50` | Higher is offered first. |
| `authenticators($user, $stored)` | the stored rows with this key | The user's authenticators. Return virtual ones for state kept elsewhere. |
| `challenge($attempt, $authenticator)` | `[]` | Extra props for the challenge page. Called every time the page loads, so it must be safe to repeat. |
| `rules()` | `code` required, up to 64 characters | Validation for a verification request. |
| `limits($request, $attempt)` | per account and per IP, from config | Rate limits. See [Rate Limiting](security.md#rate-limiting). |
| `errorKey()` | `code` | The form field failures are reported on. |
| `present($authenticator)` | `factor`, `id`, `name` | How the authenticator appears on the challenge page and in "try another way". |

Helpers on `Keyring\Factors\Factor`:

- `verified($authenticator, $categories = null, $phishingResistant = null)` builds the `Verification`.
- `consume($authenticator, $callback)` reloads the authenticator with a row lock inside a transaction, and saves it if your callback returns `true`. Use it for anything single-use, so two requests with the same proof can't both pass.
- `makeAuthenticator($attributes)` makes an unsaved authenticator of the configured model.
- `nameFrom($request, $default)` reads the optional `name` the user typed, trimmed and cut to 64 characters, or returns the default.
- `normalizeCode($code)` strips spaces and dashes.

`verify()` runs inside the timebox and after rate limiting, so you don't need to handle either.

### Optional Contracts

Implement these as well when they apply:

| Contract | Means | Methods |
|---|---|---|
| `Keyring\Contracts\PrimaryFactor` | It can start a login by identifying the user (`POST /login/{key}`). | `startsLogin()` says whether it can, as configured (WebAuthn returns `false` for security keys). `identify($request)` returns the authenticator the request is for, or `null`. It must take the same time whether or not a user is found. `identificationRules()` validates the identifying fields. |
| `Keyring\Contracts\DiscoverableFactor` | A primary factor that needs no username, like a passkey. | `loginOptions($request)` returns what the browser needs, served at `GET /login/{key}/options`. |
| `Keyring\Contracts\Enrollable` | Users can add it themselves. | `beginEnrollment()`, `enrollmentRules()`, `confirmEnrollment()` and `multiple()`. See below. |
| `Keyring\Contracts\SendsCodes` | It sends something when asked. | `send($attempt, $authenticator)`, called by `POST .../{key}/send`. |

An `Enrollable` factor enrolls in two steps. `beginEnrollment($user, $request)` returns a `Keyring\Enrollment\Enrollment`, built with `Enrollment::make()`: its props go to the browser, and only its state stays in the session, for 15 minutes. `confirmEnrollment($user, $enrollment, $request)` checks the proof against that state and returns an unsaved authenticator, or `null`. Keyring saves it. Return `false` from `multiple()` if confirming a new one should replace the old one, as recovery codes and email codes do.

`enrollmentRules()` validates the confirm request. On `Keyring\Factors\Factor` it defaults to the factor's `rules()` plus an optional `name`, so a name can be given when confirming as well as when beginning.

```php
use Keyring\Enrollment\Enrollment;

public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
{
    $serial = Str::random(12);

    return Enrollment::make($this->key(), props: ['serial' => $serial], state: ['serial' => $serial]);
}
```

## Showing a Factor in the Frontend

The challenge page picks a component by factor key. Add one line to `resources/js/keyring/factors.ts` for each new factor. A code factor can reuse the published `Code` component:

```ts
'sms': defineAsyncComponent(() => import('./factors/Code.vue')),
```

See [Frontend](frontend.md#the-challenge-page).

## Using Your Own Authenticator Model

To add relationships or methods, extend the model and tell Keyring about it:

```php
use App\Models\Authenticator;

Keyring::useAuthenticatorModel(Authenticator::class);
```

Your model must extend `Keyring\Models\Authenticator`.
