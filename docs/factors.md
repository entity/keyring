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

A **factor** is a way of proving who you are, such as a password, an authenticator app, or a passkey. Every factor implements the same `Keyring\Contracts\Factor` contract, so adding one never needs new routes, controllers, or tables.

An **authenticator** is one user's instance of a factor. That might be the authenticator app on their phone, the security key on their keychain, or their set of recovery codes. Authenticators are `Keyring\Models\Authenticator` rows in `keyring_authenticators`. A user may have as many as the factor allows. Factors that keep their state somewhere else, like the password on the `users` table, appear as unsaved "virtual" authenticators.

Each factor has a **key**, such as `totp` or `passkey`. You'll see the key in URLs like `/login/challenge/totp`, in the `factor` column, and in the frontend's factor map. Keys must match `[a-z0-9-]+`, and `challenge` is reserved.

## Registering Factors

To register factors, add them to the `boot()` method of your `KeyringServiceProvider`:

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

If you don't call `Keyring::factors`, Keyring uses the password alone. The `keyring:install` command writes this list for the sign-in methods you pick.

Registering a factor only makes it available. To let users add authenticators for it themselves, turn on [`Features::manageAuthenticators()`](authenticators.md).

NIST SP 800-63B-4 asks for at least one phishing-resistant option wherever AAL2 is offered (Sec. 2.2.2). Passkeys are one.

The list accepts class names (resolved from the container), instances, and closures that receive the container:

```php
Keyring::factors([
    Password::class,
    fn ($app) => $app->make(Totp::class, ['window' => 0, 'issuer' => 'Acme Staff']),
    new RecoveryCodes(count: 10),
]);
```

You may use `Keyring::extend` to add a factor without replacing the list. This is handy in a package:

```php
Keyring::extend('sms', fn ($app) => $app->make(SmsCode::class));
```

Keyring registers the factor under the first argument. The factor's `key` method must return the same value, or Keyring throws an `InvalidArgumentException` when it resolves the factors.

Removing a factor from the list doesn't delete anyone's authenticators. A user who still has authenticators for an unregistered factor can't sign in or step up. Keyring can't check those authenticators, and skipping them would let the password alone through. Those users see `keyring::keyring.unavailable`, and Keyring reports a `Keyring\Exceptions\UnregisteredFactor` that names the factor.

To fix this, register the factor again, or delete or migrate those rows. Until you do, code that calls `$authenticator->factor()` on such a row throws `Keyring\Exceptions\UnknownFactor`. That exception is an HTTP exception, so an unregistered factor key in a URL gives a `404`.

## Built-in Factors

| Key | Class | Categories | Starts a Sign In | Users Add It | Priority |
|---|---|---|---|---|---|
| `password` | `Password` | knowledge | yes | no | 40 |
| `totp` | `Totp` | possession | no | yes | 60 |
| `email-code` | `EmailCode::asExtraStep()` | address (not a factor) | no | yes, one | 30 |
| `recovery` | `RecoveryCodes` | possession | no | yes, one set | 0 |
| `passkey` | `WebAuthn::passkeys()` | possession, plus inherence when the user was verified | yes | yes | 100 |
| `security-key` | `WebAuthn::securityKeys()` | possession, plus inherence when the user was verified | no | yes | 90 |

When Keyring needs another factor, it offers the user's default authenticator first, and then the rest in order of priority.

### Password

The password stays in your `users` table, so password resets and Laravel's own helpers keep working. A user without a password doesn't have this authenticator. You can't add or remove it through Keyring's authenticator routes. Instead, it changes through the [password change](protected-changes.md#changing-the-password) and [reset](protected-changes.md#resetting-the-password) flows.

When a sign in starts with an unknown address, Keyring still runs a password hash, so the response takes the same time either way. If your hashing settings have changed, a correct password is rehashed.

Keyring puts a typed password into Unicode's NFC form before it checks the password. It does this for every password its routes set, so a password matches however the device composed its characters. See [Password Rules](protected-changes.md#password-rules).

### Authenticator Apps (TOTP)

These are time-based one-time passwords (RFC 6238). Enrolling returns a 32 character secret, an `otpauth://` URL, and an SVG QR code.

By default, a code is accepted for one 30 second time step either side of now. The `window` constructor argument controls this, so one code can work for up to about 90 seconds. **That default does not meet OWASP ASVS 5.0.0 requirement 6.5.5**, which gives a TOTP a maximum lifetime of 30 seconds. Keyring keeps the default anyway. RFC 6238 recommends accepting one earlier step for the time a code takes to arrive (Sec. 5.2), and it allows a limit on clock drift in either direction (Sec. 6). Without any window, a code typed near the end of its step is refused, and that would turn away a large share of honest sign ins.

To meet 6.5.5 to the letter, give the factor a window of zero, so a code only works during its own step:

```php
Keyring::factors([
    Password::class,
    fn ($app) => $app->make(Totp::class, ['window' => 0]),
    RecoveryCodes::class,
]);
```

The widest window allowed is one step (`Totp::MAX_WINDOW`). Any other value throws a `LogicException` when the factor is built.

Each authenticator remembers the last time step it accepted, under a row lock, so a code can't be used twice, even by two requests at the same moment. A user can have several authenticator apps.

Codes use HMAC-SHA1 by default. This is a compatibility choice, not a matter of preference. It's the digest RFC 6238 defaults to, and it's the only one every authenticator app generates. Some widely used apps have ignored a request for any other digest, and they keep showing SHA-1 codes that never match. Google Authenticator's own key format notes said so for years. The user then can't finish adding the app. OWASP ASVS lists HMAC-SHA-1 as a legacy algorithm, which it allows for compatibility like this. The weakness that retired SHA-1 for signatures is finding two inputs with the same hash. That doesn't help anyone guess a code keyed with a secret they don't have.

If you control which apps your users have, set the factor up with SHA-256 or SHA-512:

```php
fn ($app) => $app->make(Totp::class, ['algorithm' => 'sha256']),
```

With that setting, the `otpauth://` URL and the QR code say `algorithm=SHA256`. Enrolling also returns the algorithm as `algorithm`, so you can show it beside the secret for anyone typing it in. Each authenticator keeps the digest it was set up with. Changing the setting only affects apps added afterwards, and nobody has to enroll again. The secret is 160 random bits, whichever digest is used.

### Email Codes

This factor sends an eight digit code to the user's current email address. It's opt-in, because NIST SP 800-63B-4 doesn't accept email as an authenticator at any level (Sec. 3.1.3.1). Whoever controls the inbox can also reset the password. For a user with nothing beside their password, the inbox is the whole account. Registering plain `EmailCode::class` throws an exception that says so. If you want to accept that risk anyway, register the factor like this:

```php
Keyring::factors([Password::class, Totp::class, EmailCode::asExtraStep()]);
```

By default, codes are eight digits long, last ten minutes, and allow five wrong guesses. If you'd like different limits, pass the new values:

```php
EmailCode::asExtraStep(length: 6, expireAfter: '5m', maxGuesses: 3)
```

Six digits is the shortest a code can be, and ten minutes is the longest it can last. These are the bounds OWASP ASVS 5.0.0 sets for codes sent out of band (requirements 6.5.4 and 6.5.5). Asking for less or for longer throws a `LogicException` on that line.

The code goes out in your `verification_code` [notification](security-log-and-emails.md#emails-a-flow-needs). The `keyring:install` command publishes and registers that notification.

Whatever limits you choose, each code:

- is only sent when the user asks for it (see [Sending Codes](sign-in-flow.md#sending-codes)), and never because they opened the challenge page,
- shares its wrong-guess limit with every other code sent for that sign in,
- is replaced by any newer code,
- works once,
- is stored as a keyed hash, never in plain text.

Sending a new code doesn't reset the wrong guess count. Once the limit is reached, the attempt is over, and the user has to start signing in again.

Keyring keeps the code, its guess count, and whether it was used on the server, in the cache store your rate limits use (`cache.limiter`). It doesn't keep them in the session. That means everything above holds on any session driver, including Laravel's `cookie` driver, where a browser can send back an earlier copy of its session. The store has to keep its keys from one request to the next, as the rate limits already require. With the `array` store, a code is forgotten before it can be typed. Clearing the store drops the codes that are waiting, and the user then asks for another one.

Enrolling sends a code to the current address, and the user types it in to confirm. Every copy would go to the same address, so a user has at most one. Enrolling again replaces it. Wrong guesses are limited the same way across an enrollment, including when it's started again. Once the limit is reached, no code is sent until 15 minutes ([`enrollments.keep_for`](configuration.md#account-changes-and-enrollment)) after the first wrong guess. Guesses are counted per user, so another browser doesn't get guesses of its own. Email codes are only as strong as the inbox, so they aren't phishing resistant.

#### What Turning Email Codes On Means

An emailed code is a step at sign in, not a second factor. Its category is `Category::Address`, which counts toward no [assurance level](policies.md#assurance-levels). If an account's only sign-in methods are a password and an email code, keep these points in mind:

- Under a policy with `ifEnrolled()`, such as the default, signing in asks for both. A policy that asks for two factors outright, `Requirement::aal2()` without `ifEnrolled()`, turns the account away. `Requirement::steps(2)` takes a password and a code instead.
- The session is AAL1. It doesn't satisfy `keyring:aal2`, which sends the user to your [`enrollment_url`](configuration.md#account-changes-and-enrollment) to add a real second factor. The [`keyring.enrolled`](policies.md#requiring-a-second-factor) middleware does the same.
- The account doesn't count as having a second factor. Its password needs the [longer minimum](protected-changes.md#password-rules), an [email change](protected-changes.md#changing-the-email-address) is confirmed from the current address too, and "don't ask again on this device" isn't offered or granted.
- It gets no recovery codes. They stand in for a lost factor, and the inbox that codes go to is how the account is recovered anyway.
- The user can add a real second factor. The [fresh verification](step-up.md#fresh-verification) asks for the password and an emailed code before that happens. From then on, the emailed code isn't asked for or offered at sign in, and it can't stand in for the possession factor that a fresh verification wants.

If your app has routes behind `keyring:aal2`, or it tells users their account has two-factor authentication, offer an authenticator app or passkeys alongside email codes, and send users to them.

### Recovery Codes

Recovery codes come as a set of eight single-use codes, each in the form `xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xx`. They're shown once. Each code holds 16 random bytes, which is the 128 bits OWASP ASVS asks for in a value that mustn't be guessed. Those bytes are written as 26 base32 characters. Keyring stores each code as a keyed hash, using HMAC-SHA-256 under a key derived from `APP_KEY` for recovery codes alone. OWASP ASVS 5.0.0 requirement 6.5.2 allows that for a code with 112 random bits or more. Below that, it asks for a slow, salted password hash instead. So Keyring stores and accepts nothing shorter. `secretFor()` throws an `InvalidArgumentException` for a code in any other form, and a code typed in another form never matches. Typing codes is case-insensitive, and spaces and dashes are ignored. Like TOTP, each code is used up under a row lock.

There is one other form, which is Fortify's. It's used for the sets that [`keyring:import`](upgrading-from-fortify.md#importing-two-factor-data) brings across. Those codes are 20 letters and digits, with 119 random bits. They only have that many bits while their case counts, so an imported code has to be typed exactly as it was shown.

A user has at most one set. Generating a new set replaces the old one. Users get a set automatically with their first extra factor. Recovery codes are a fallback, so they can never be the default authenticator. See [Recovery Codes](authenticators.md#recovery-codes).

The factor's key is available as `RecoveryCodes::KEY` (`recovery`). Use it in code that looks up a user's set.

When you rotate `APP_KEY`, put the old key in `APP_PREVIOUS_KEYS`, and existing codes keep working.

Once every code is used, the set no longer counts as a factor. Policies and step-up stop asking for it.

### Passkeys and Security Keys

Both use one WebAuthn driver, with two profiles. Passkeys are discoverable and always verify the user, so they can sign in on their own. Security keys are a second factor. You may limit them to keys whose maker vouches for them by calling `requireAttestation()`. See [Passkeys & Security Keys](passkeys.md).

## Categories

Every verification proves one or more **categories**, from `Keyring\Enums\Category`:

- `Knowledge`: something the user knows, like a password.
- `Possession`: something they have, such as a phone, a key, or saved recovery codes.
- `Inherence`: something they are, such as a fingerprint checked by their authenticator.
- `Address`: something sent to an address of theirs, such as a code by email. This one isn't an authentication factor. It shows that whoever answers can read the address, and NIST SP 800-63B-4 doesn't accept email as an authenticator. A verification with only this category is a step that an application can ask for, and it never raises the session's level. Use `Category::authenticates()` to tell the two kinds apart.

Policies count distinct categories, not verifications, so a password and a PIN together are still one factor. See [Policies](policies.md).

As NIST SP 800-63B-4 does (Sec. 2.2.1), AAL2 and AAL3 need `Possession` among what was proved. A biometric is only accepted together with the authenticator it unlocks. So if you write a factor that checks something the user is, report `Inherence` only when a device they hold made the check, and report `Possession` along with it. A factor that reports `Inherence` alone can be asked for as a second step, but the session stays at AAL1.

A factor declares the categories it expects in the `categories` method, and Keyring uses that to plan what to offer. The categories that count are the ones in the `Verification` returned by `verify`. That's how a security key only counts as inherence when it actually verified the user that time.

## Writing a Code Factor

If your factor sends a one-time code, extend `Keyring\Factors\CodeFactor`. It handles sending, checking, expiry, single use, guess limits, resending, and enrollment. It also keeps each code's state on the server (`Keyring\Factors\SentCodes`), in the same way as it does for [email codes](#email-codes). A code only verifies the authenticator it was sent to, so a user with two phones can't send a code to one and type it in against the other. You provide a key, a default name, and how the code is delivered:

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
| `$length` | `8` | Digits per code, and at least `6`. |
| `$ttl` | `600` | Seconds a code stays valid, and at most `600`. |
| `$maxGuesses` | `5` | Wrong guesses allowed per sign in or enrollment, no matter how many codes it sends. |

Keyring checks `$length` and `$ttl` when it resolves your factors. If a code would be shorter than six digits, or would last longer than ten minutes, Keyring throws a `LogicException` that names the factor (OWASP ASVS 5.0.0, requirements 6.5.4 and 6.5.5). The bounds are `CodeFactor::MIN_LENGTH` and `CodeFactor::MAX_TTL`.

Code factors count as possession and have a priority of 30. You may override `categories`, `priority`, or `present` to change that.

Possession is the right category for a code sent to a device the user holds, such as a text message to their phone. NIST restricts that kind of code without ruling it out (see the [SMS recipe](recipes.md#sms-codes)). A code sent somewhere that only needs a password to read, as email does, isn't a factor. Return `[Category::Address]` from `categories`, as `EmailCode` does, and Keyring treats it as a step that reaches no level.

### Collecting Details at Enrollment

To collect something such as a phone number when the user adds the factor, override the `newAuthenticator` method. It receives the request that begins enrollment, and it returns an unsaved authenticator. Whatever you put in `secret` (encrypted at rest) or `meta` is carried through the enrollment and saved once it's confirmed. Keyring doesn't validate the begin request for you, so validate it in this method:

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

The `deliver` method then reads the number from `$authenticator->secret`.

Because codes go to the address on the authenticator, confirming the enrollment proves the user can receive them.


For a complete example, see the [SMS recipe](recipes.md#sms-codes). A factor that starts a sign in, such as [a social login](recipes.md#social-login-with-socialite), is covered in [Writing Any Other Factor](#writing-any-other-factor).

## Writing Any Other Factor

Any other factor implements `Keyring\Contracts\Factor`. Extending `Keyring\Factors\Factor` gives you defaults for everything except `key`, `categories`, and `verify`.

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

The contract's methods are:

| Method | Default in `Factor` | Purpose |
|---|---|---|
| `key` | none | The factor's key. |
| `categories($authenticator)` | none | The categories it's expected to prove. Use `[Category::Address]` for a factor that NIST doesn't accept as an authenticator. |
| `verify($attempt, $authenticator, $request)` | none | Checks the proof. Returns a `Verification`, or `null` when the proof is wrong. |
| `phishingResistant($authenticator)` | `false` | Whether the proof is bound to your origin. Only WebAuthn should return `true`. |
| `deviceBound($authenticator)` | `false` | Whether the secret can't leave its device, according to the authenticator itself. |
| `attested($authenticator)` | `false` | Whether something else vouches for what the authenticator is, as a WebAuthn attestation checked when it was added does. AAL3 accepts a device-bound key only when this is also `true`. |
| `priority` | `50` | Higher numbers are offered first. |
| `authenticators($user, $stored)` | the stored rows with this key | The user's authenticators. Return virtual ones for state that's kept elsewhere. |
| `challenge($attempt, $authenticator)` | `[]` | Extra props for the challenge page. Keyring calls it every time the page loads, so it must be safe to repeat. |
| `rules` | `code` required, up to 64 characters | Validation rules for a verification request. Keyring checks them against the request body, not the query string of a `POST`, so a field you require can't arrive in the URL. |
| `limits($request, $attempt)` | per account and per IP, from config | Rate limits. See [Rate Limiting](security.md#rate-limiting). |
| `errorKey` | `code` | The form field that failures are reported on. |
| `present($authenticator)` | `factor`, `id`, `name`, `createdAt`, `lastUsedAt` | How the authenticator appears on a settings page, and in the responses to adding or renaming one. The challenge page and "try another way" get the same, without `createdAt` and `lastUsedAt`. |

These helpers come from `Keyring\Factors\Factor`:

- Use `verified($authenticator, $categories = null, $phishingResistant = null, $deviceBound = null)` to build the `Verification`.
- Use `consume($authenticator, $callback)` for anything single-use. It reloads the authenticator with a row lock inside a transaction, and it saves the authenticator if your callback returns `true`. So two requests with the same proof can't both pass.
- Use `makeAuthenticator($attributes)` to make an unsaved authenticator of the configured model.
- `nameFrom($request, $default)` reads the optional `name` the user typed. Keyring trims it and cuts it to 64 characters, or returns the default.
- Use `normalizeCode($code)` to strip spaces and dashes from a code.

The `verify` method runs inside the timebox and after rate limiting, so you don't need to handle either yourself.

### Optional Contracts

Implement these as well when they apply:

| Contract | Means | Methods |
|---|---|---|
| `Keyring\Contracts\PrimaryFactor` | It can start a sign in by identifying the user (`POST /login/{key}`). | `startsLogin`, `answersChallenges`, `identify`, `stall`, and `identificationRules`. See below. |
| `Keyring\Contracts\DiscoverableFactor` | A primary factor that needs no username, such as a passkey. | `loginOptions($request)` returns what the browser needs. It's served under `options` at `GET /login/{key}/options`. |
| `Keyring\Contracts\Enrollable` | Users can add it themselves. | `beginEnrollment`, `enrollmentRules`, `confirmEnrollment`, and `multiple`. See below. |
| `Keyring\Contracts\SendsCodes` | It sends something when asked. | `send($attempt, $authenticator)`, called by `POST .../{key}/send`. |

A `PrimaryFactor` has five methods:

- `startsLogin()` says whether the factor can start a sign in, as configured. WebAuthn returns `false` for security keys.
- `answersChallenges()` says whether `verify()` checks a proof of its own. Return `false` when the proof is who `identify()` found, as with a social login. Keyring then keeps the factor off the challenge and confirm pages, which never call `identify()`.
- `identify($request)` returns the authenticator the request is for, or `null`. An authenticator whose user Keyring's guard wouldn't load back counts as `null`. The method must take the same time whether or not a user is found.
- `stall()` spends the time `verify()` would take. Keyring calls it instead when it turns away whoever `identify()` found, without looking at their proof. That happens for an account that `allowSignInWhen()` keeps out, or one whose own rate limit refuses. The base factor's `stall()` does nothing, so only write one when checking a proof is slow, as a password hash is.
- `identificationRules()` validates the identifying fields.

An `Enrollable` factor enrolls in two steps. `beginEnrollment($user, $request)` returns a `Keyring\Enrollment\Enrollment`, which you build with `Enrollment::make()`. Its props go to the browser, and only its state stays in the session, for 15 minutes. `confirmEnrollment($user, $enrollment, $request)` checks the proof against that state. It returns an unsaved authenticator, or `null`. Keyring saves the authenticator once. An enrollment that has already added its authenticator can't be confirmed again, even from an earlier copy of the session. Keyring also counts the authenticator as verified in the session. So only return one when the proof really shows that the new authenticator works. Return `false` from `multiple` if confirming a new one should replace the old one, as recovery codes and email codes do.

The `enrollmentRules` method validates the confirm request. On `Keyring\Factors\Factor`, it defaults to the factor's `rules` plus an optional `name`, so a name can be given when confirming, as well as when beginning.

Here's a `beginEnrollment` method that generates a serial number to show the user:

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
