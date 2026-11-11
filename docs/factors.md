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
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;

Keyring::factors([
    Password::class,
    WebAuthn::passkeys(),
    WebAuthn::securityKeys(),
    Totp::class,
    RecoveryCodes::class,
]);
```

Without `Keyring::factors()`, Keyring uses the password alone. `keyring:install` writes the list for the methods you pick. To let users set the others up, turn on [`Features::manageAuthenticators()`](authenticators.md). NIST SP 800-63B-4 asks for at least one phishing-resistant option wherever AAL2 is offered (Sec. 2.2.2), which passkeys are.

The list accepts class names (resolved from the container), instances, and closures that receive the container:

```php
Keyring::factors([
    Password::class,
    fn ($app) => $app->make(Totp::class, ['window' => 0, 'issuer' => 'Acme Staff']),
    new RecoveryCodes(count: 10),
]);
```

`Keyring::extend()` adds a factor without replacing the list, which is handy in a package:

```php
Keyring::extend('sms', fn ($app) => $app->make(SmsCode::class));
```

The factor is registered under the first argument, and its `key()` must return the same value, or Keyring throws an `InvalidArgumentException` when it resolves the factors.

Removing a factor from the list doesn't delete anyone's authenticators. A user who still has authenticators for a factor that isn't registered can't sign in or step up: Keyring can't check those, and skipping them would let the password alone through. They see `keyring::keyring.unavailable`, and Keyring reports a `Keyring\Exceptions\UnregisteredFactor` naming the factor, so register it again or delete those rows. Code that calls `$authenticator->factor()` on such a row throws `Keyring\Exceptions\UnknownFactor`, so delete or migrate those rows if you drop a factor for good. `UnknownFactor` is an HTTP exception, so an unregistered factor key in a URL gives a `404`.

## Built-in Factors

| Key | Class | Categories | Starts a login | Users add it | Priority |
|---|---|---|---|---|---|
| `password` | `Password` | knowledge | yes | no | 40 |
| `totp` | `Totp` | possession | no | yes | 60 |
| `email-code` | `EmailCode::asExtraStep()` | address (not a factor) | no | yes, one | 30 |
| `recovery` | `RecoveryCodes` | possession | no | yes, one set | 0 |
| `passkey` | `WebAuthn::passkeys()` | possession, plus inherence when the user was verified | yes | yes | 100 |
| `security-key` | `WebAuthn::securityKeys()` | possession, plus inherence when the user was verified | no | yes | 90 |

When Keyring needs another factor, it offers the user's default authenticator first, then the rest by priority.

### Password

The password stays in your `users` table, so password resets and Laravel's own helpers keep working. A user without a password doesn't have this authenticator. It can't be added or removed through Keyring's authenticator routes; it changes through the [password change](protected-changes.md#changing-the-password) and [reset](protected-changes.md#resetting-the-password) flows.

When a login starts with an unknown address, Keyring still runs a password hash, so the response takes the same time either way. A correct password is rehashed if your hashing settings changed.

A typed password is put in Unicode's NFC form before it's checked, like every password Keyring's routes set, so it matches whichever way the device composed its characters. See [Password Rules](protected-changes.md#password-rules).

### Authenticator Apps (TOTP)

Time-based one-time passwords (RFC 6238). Enrolling returns a 32 character secret, an `otpauth://` URL and an SVG QR code.

By default a code is accepted one 30 second time step either side of now (the `window` constructor argument), so one code can work for up to about 90 seconds. **That default does not meet OWASP ASVS 5.0.0 requirement 6.5.5**, which gives a TOTP a maximum lifetime of 30 seconds. Keyring keeps it because RFC 6238 recommends accepting one earlier step for the time a code takes to arrive (Section 5.2) and allows a limit on clock drift either way (Section 6), and with none a code typed near the end of its step is refused, which is a large share of honest sign ins.

To meet 6.5.5 to the letter, give the factor a window of zero, so a code only works during its own step:

```php
Keyring::factors([
    Password::class,
    fn ($app) => $app->make(Totp::class, ['window' => 0]),
    RecoveryCodes::class,
]);
```

One step is the widest window there is (`Totp::MAX_WINDOW`). Anything else throws a `LogicException` when the factor is built.

Each authenticator remembers the last time step it accepted, under a row lock, so a code can't be used twice, even by two requests at the same moment.

A user can have several authenticator apps.

Codes are made with HMAC-SHA1 by default. That's a compatibility choice, not a preference: it's what RFC 6238 defaults to and the only digest every authenticator app makes. Some widely used apps have ignored a request for anything else (Google Authenticator's own key format notes said so for years) and gone on showing SHA-1 codes, which then never match, so the user can't finish adding the app. OWASP ASVS lists HMAC-SHA-1 as a legacy algorithm, allowed for compatibility like this. The weakness that retired SHA-1 for signatures is finding two inputs with the same hash, which doesn't help anyone guess a code keyed with a secret they don't have.

If you control which apps your users have, set the factor up with SHA-256 or SHA-512:

```php
fn ($app) => $app->make(Totp::class, ['algorithm' => 'sha256']),
```

The `otpauth://` URL and the QR code then say `algorithm=SHA256`, and enrolling returns it as `algorithm` to show beside the secret for anyone typing it in. Each authenticator keeps the digest it was set up with, so changing the setting only affects apps added afterwards and nobody has to enroll again. The secret is 160 random bits whichever digest is used.

### Email Codes

An eight digit code sent to the user's current email address. It's opt-in, because NIST SP 800-63B-4 doesn't accept email as an authenticator at any level (Sec. 3.1.3.1): whoever controls the inbox can also reset the password, so for a user with nothing else beside their password, the inbox is the whole account. Registering plain `EmailCode::class` throws an exception that says so. To accept that risk:

```php
Keyring::factors([Password::class, Totp::class, EmailCode::asExtraStep()]);
```

Codes are eight digits, last ten minutes and allow five wrong guesses. To change that:

```php
EmailCode::asExtraStep(length: 6, expireAfter: '5m', maxGuesses: 3)
```

Six digits is the shortest a code can be and ten minutes the longest it can last, the bounds OWASP ASVS 5.0.0 sets for codes sent out of band (requirements 6.5.4 and 6.5.5). Asking for less or for longer throws a `LogicException` on that line.

The code goes out in your `verification_code` [notification](security-log-and-emails.md#emails-a-flow-needs), which `keyring:install` publishes and registers.

A code:

- is only sent when the user asks (see [Sending Codes](sign-in-flow.md#sending-codes)), never just by opening the challenge page,
- expires after 10 minutes,
- allows five wrong guesses per sign in, across every code sent for it,
- is replaced by any newer code,
- works once,
- is stored as a keyed hash, never in plain text.

Sending a new code doesn't reset the wrong guess count. Once the limit is reached the attempt is over, and the user has to start signing in again.

The code, its guess count and the fact that it was used are kept on the server, in the cache store your rate limits use (`cache.limiter`), not in the session. So all of the above holds on any session driver, including Laravel's `cookie` driver, where a browser can send back an earlier copy of its session. That store has to keep its keys from one request to the next, as the rate limits already need: with the `array` store a code is forgotten before it can be typed. Clearing it drops the codes that are waiting, and the user asks for another.

Enrolling sends a code to the current address, and the user types it to confirm. Every copy would go to the same address, so a user has at most one: enrolling again replaces it. Wrong guesses are limited the same way across an enrollment, including when it's started again, and at the limit no code is sent until 15 minutes ([`enrollments.keep_for`](configuration.md#account-changes-and-enrollment)) after the first wrong guess. They're counted per user, so another browser doesn't get guesses of its own. Email codes are only as strong as the inbox, so they aren't phishing resistant.

#### What Turning Email Codes On Means

An emailed code is a step at sign in, not a second factor. Its category is `Category::Address`, which counts toward no [assurance level](policies.md#assurance-levels). For an account whose only sign-in methods are a password and an email code:

- Signing in asks for both under a policy with `ifEnrolled()`, such as the default. A policy that asks for two factors outright, `Requirement::aal2()` without `ifEnrolled()`, turns the account away; `Requirement::steps(2)` takes a password and a code.
- The session is AAL1. `keyring:aal2` isn't satisfied by it and sends the user to your [`enrollment_url`](configuration.md#account-changes-and-enrollment) to add a real second factor, and so does [`keyring.enrolled`](policies.md#requiring-a-second-factor).
- The account doesn't count as having a second factor: its password needs the [longer minimum](protected-changes.md#password-rules), an [email change](protected-changes.md#changing-the-email-address) is confirmed from the current address too, and "don't ask again on this device" isn't offered or granted.
- It gets no recovery codes. They stand in for a lost factor, and the inbox a code goes to is how the account is recovered anyway.
- The user can add a real second factor: the [fresh verification](step-up.md#fresh-verification) before it asks for the password and an emailed code. From then on the emailed code isn't asked for or offered at sign in, and can't stand in for the possession factor a fresh verification wants.

If your app has routes behind `keyring:aal2`, or tells users their account has two-factor authentication, offer an authenticator app or passkeys next to email codes and send users to them.

### Recovery Codes

Eight single-use codes in the form `xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xx`, shown once. Each is 16 random bytes, the 128 bits OWASP ASVS asks of a value that mustn't be guessed, written as 26 base32 characters, and is stored as a keyed hash (HMAC-SHA-256 under a key derived from `APP_KEY` for recovery codes alone). OWASP ASVS 5.0.0 requirement 6.5.2 allows that for a code with 112 random bits or more, and asks for a slow, salted password hash below it, so Keyring stores and accepts nothing shorter: `secretFor()` throws an `InvalidArgumentException` for a code in any other form, and one typed in another form never matches. Typing them is case-insensitive, and spaces and dashes are ignored. Like TOTP, each code is used up under a row lock.

The one other form is Fortify's, for sets [`keyring:import`](upgrading-from-fortify.md#importing-two-factor-data) brings across: 20 letters and digits, 119 random bits. Those have that many only while their case counts, so an imported code has to be typed as it was shown.

A user has at most one set. Generating a new set replaces the old one. Users get a set automatically with their first extra factor. Recovery codes are a fallback, so they can never be the default authenticator. See [Recovery Codes](authenticators.md#recovery-codes).

The factor's key is available as `RecoveryCodes::KEY` (`recovery`), for code that looks the set up.

The hashes are keyed with a key derived from `APP_KEY` for recovery codes alone. When you rotate it, put the old key in `APP_PREVIOUS_KEYS` and existing codes keep working.

Once every code is used, the set no longer counts as a factor, so policies and step-up stop asking for it.

### Passkeys and Security Keys

One WebAuthn driver with two profiles. Passkeys are discoverable and always verify the user, so they can sign in on their own. Security keys are a second factor, and can be limited to keys whose maker vouches for them with `requireAttestation()`. See [Passkeys & Security Keys](passkeys.md).

## Categories

Every verification proves one or more **categories**, from `Keyring\Enums\Category`:

- `Knowledge`: something the user knows, like a password.
- `Possession`: something they have, like a phone, a key or saved recovery codes.
- `Inherence`: something they are, like a fingerprint checked by their authenticator.
- `Address`: something sent to an address of theirs, like a code by email. This one isn't an authentication factor: it shows that whoever answers can read the address, and NIST SP 800-63B-4 doesn't accept email as an authenticator. A verification with only this category is a step an app can ask for, and never raises the session's level. `Category::authenticates()` tells the two kinds apart.

Policies count distinct categories, not verifications, so a password and a PIN together are still one factor. See [Policies](policies.md).

AAL2 and AAL3 need `Possession` among what was proved, as NIST SP 800-63B-4 does (Sec. 2.2.1): a biometric is only taken together with the authenticator it unlocks. So if you write a factor that checks something the user is, report `Inherence` only when the check was made by a device they hold, and report `Possession` with it. A factor that reports `Inherence` alone can be asked for as a second step, and the session stays at AAL1.

A factor declares the categories it expects in `categories()`, which Keyring uses to plan what to offer. The categories that count are the ones in the `Verification` returned by `verify()`. That's how a security key only counts as inherence when it actually verified the user that time.

## Writing a Code Factor

[Recipes](recipes.md#sms-codes) has a complete SMS factor, and [a social login](recipes.md#social-login-with-socialite) written as a factor that starts a sign in.

Factors that send a one-time code extend `Keyring\Factors\CodeFactor`. It implements sending, checking, expiry, single use, guess limits, resending and enrollment, and keeps each code's state on the server (`Keyring\Factors\SentCodes`) as it does for [email codes](#email-codes). A code only verifies the authenticator it was sent to, so a user with two phones can't send to one and type the code against the other. You provide a key, a default name and the delivery:

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
| `$length` | `8` | Digits per code, `6` at least. |
| `$ttl` | `600` | Seconds a code stays valid, `600` at most. |
| `$maxGuesses` | `5` | Wrong guesses allowed per sign in or enrollment, however many codes it sends. |

Keyring checks `$length` and `$ttl` when it resolves your factors, and throws a `LogicException` naming the factor when a code would be shorter than six digits or last longer than ten minutes (OWASP ASVS 5.0.0, requirements 6.5.4 and 6.5.5). The bounds are `CodeFactor::MIN_LENGTH` and `CodeFactor::MAX_TTL`.

Code factors count as possession and have priority 30. Override `categories()`, `priority()` or `present()` to change that.

Possession is right for a code sent to a device the user holds, such as a text message to their phone. NIST restricts that one without ruling it out (see the [SMS recipe](recipes.md#sms-codes)). A code sent somewhere that only takes a password to read, as email does, isn't a factor: return `[Category::Address]` from `categories()`, as `EmailCode` does, and Keyring treats it as a step that reaches no level.

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
            // Check the posted code against $locked, and record that it was
            // used (for example in $locked->withMeta(...)).
            return app(TokenServer::class)->check($locked->secret, (string) $request->post('code'));
        });

        return $valid ? $this->verified($authenticator) : null;
    }
}
```

The contract's methods:

| Method | Default in `Factor` | Purpose |
|---|---|---|
| `key()` | none | The factor's key. |
| `categories($authenticator)` | none | The categories it's expected to prove. `[Category::Address]` for a factor that isn't an authenticator NIST accepts. |
| `verify($attempt, $authenticator, $request)` | none | Check the proof. Return a `Verification`, or `null` when it's wrong. |
| `phishingResistant($authenticator)` | `false` | Whether the proof is bound to your origin. Only WebAuthn should say yes. |
| `deviceBound($authenticator)` | `false` | Whether the secret can't leave its device, by the authenticator's own account. |
| `attested($authenticator)` | `false` | Whether something else vouches for what the authenticator is, as a WebAuthn attestation checked when it was added does. AAL3 takes a device-bound key only when this is true too. |
| `priority()` | `50` | Higher is offered first. |
| `authenticators($user, $stored)` | the stored rows with this key | The user's authenticators. Return virtual ones for state kept elsewhere. |
| `challenge($attempt, $authenticator)` | `[]` | Extra props for the challenge page. Called every time the page loads, so it must be safe to repeat. |
| `rules()` | `code` required, up to 64 characters | Validation for a verification request. Keyring checks them against the request's body, not the query string of a `POST`, so a field you require can't arrive in the URL. |
| `limits($request, $attempt)` | per account and per IP, from config | Rate limits. See [Rate Limiting](security.md#rate-limiting). |
| `errorKey()` | `code` | The form field failures are reported on. |
| `present($authenticator)` | `factor`, `id`, `name`, `createdAt`, `lastUsedAt` | How the authenticator appears on a settings page and in the answers to adding or renaming one. The challenge page and "try another way" get the same without `createdAt` and `lastUsedAt`. |

Helpers on `Keyring\Factors\Factor`:

- `verified($authenticator, $categories = null, $phishingResistant = null, $deviceBound = null)` builds the `Verification`.
- `consume($authenticator, $callback)` reloads the authenticator with a row lock inside a transaction, and saves it if your callback returns `true`. Use it for anything single-use, so two requests with the same proof can't both pass.
- `makeAuthenticator($attributes)` makes an unsaved authenticator of the configured model.
- `nameFrom($request, $default)` reads the optional `name` the user typed, trimmed and cut to 64 characters, or returns the default.
- `normalizeCode($code)` strips spaces and dashes.

`verify()` runs inside the timebox and after rate limiting, so you don't need to handle either.

### Optional Contracts

Implement these as well when they apply:

| Contract | Means | Methods |
|---|---|---|
| `Keyring\Contracts\PrimaryFactor` | It can start a login by identifying the user (`POST /login/{key}`). | `startsLogin()` says whether it can, as configured (WebAuthn returns `false` for security keys). `answersChallenges()` says whether `verify()` checks a proof of its own: return `false` when the proof is who `identify()` found, as with a social login, and Keyring keeps the factor off the challenge and confirm pages, which never call `identify()`. `identify($request)` returns the authenticator the request is for, or `null`. An authenticator whose user Keyring's guard wouldn't load back counts as `null`. It must take the same time whether or not a user is found. `stall()` spends the time `verify()` would: Keyring calls it instead when it turns away whoever `identify()` found without looking at their proof (an account `allowSignInWhen()` keeps out, or one whose own rate limit refuses). The base factor's does nothing, so only write one when checking a proof is slow, as a password hash is. `identificationRules()` validates the identifying fields. |
| `Keyring\Contracts\DiscoverableFactor` | A primary factor that needs no username, like a passkey. | `loginOptions($request)` returns what the browser needs, served under `options` at `GET /login/{key}/options`. |
| `Keyring\Contracts\Enrollable` | Users can add it themselves. | `beginEnrollment()`, `enrollmentRules()`, `confirmEnrollment()` and `multiple()`. See below. |
| `Keyring\Contracts\SendsCodes` | It sends something when asked. | `send($attempt, $authenticator)`, called by `POST .../{key}/send`. |

An `Enrollable` factor enrolls in two steps. `beginEnrollment($user, $request)` returns a `Keyring\Enrollment\Enrollment`, built with `Enrollment::make()`: its props go to the browser, and only its state stays in the session, for 15 minutes. `confirmEnrollment($user, $enrollment, $request)` checks the proof against that state and returns an unsaved authenticator, or `null`. Keyring saves it, once: an enrollment that has added its authenticator can't be confirmed again, even from an earlier copy of the session. It also counts it as verified in the session, so only return one when the proof really shows the new authenticator works. Return `false` from `multiple()` if confirming a new one should replace the old one, as recovery codes and email codes do.

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

The challenge page picks a component by factor key (see [Frontend](frontend.md#the-challenge-page)). Add one line to your factor map for each new factor. A code factor can reuse the component you use for TOTP:

```ts
'sms': defineAsyncComponent(() => import('./factors/Code.vue')),
```


## Using Your Own Authenticator Model

To add relationships or methods, extend the model and tell Keyring about it:

```php
use App\Models\Authenticator;

Keyring::useAuthenticatorModel(Authenticator::class);
```

Your model must extend `Keyring\Models\Authenticator`.
