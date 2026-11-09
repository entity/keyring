# The Sign In Flow

- [Introduction](#introduction)
- [Routes](#routes)
- [Signing In With a Password](#signing-in-with-a-password)
    - [Finding the User](#finding-the-user)
- [Signing In With a Passkey](#signing-in-with-a-passkey)
- [The Challenge Page](#the-challenge-page)
    - [Page Props](#page-props)
    - [Choosing an Authenticator](#choosing-an-authenticator)
    - [Verifying](#verifying)
    - [Sending Codes](#sending-codes)
- [Finishing the Login](#finishing-the-login)
- [Registration](#registration)
- [Signing Out](#signing-out)
- [The Verification Pipeline](#the-verification-pipeline)
    - [Customising the Steps](#customising-the-steps)
    - [Writing a Step](#writing-a-step)
- [Responses](#responses)
    - [Status Responses](#status-responses)
- [Pages](#pages)
- [Events](#events)

## Introduction

Signing in is a short state machine:

1. The user proves a first factor, usually their password, at `POST /login`. This identifies them.
2. Keyring asks the [policy](policies.md) what they need. If that's met, they're signed in.
3. Otherwise Keyring regenerates the session ID, saves a pending **attempt** in the session and sends them to the challenge page, which asks for the next factor. They repeat until the requirement is met.

The pending attempt is encrypted JSON in the session. It lasts `pending_login_ttl` (10 minutes by default), and ends early if the user's password changes meanwhile, so a reset also stops someone who already got past the old password, or if `keyring.guard` is no longer the guard it started under. After that, the user is sent back to the login page with `keyring::keyring.expired`.

[Step-up](step-up.md) uses the same challenge page and the same pipeline, with the purpose `confirm` instead of `login`.

## Routes

| Method | URI | Name | Purpose |
|---|---|---|---|
| `GET` | `/login` | `login` | The login page. |
| `POST` | `/login` | `login.store` | Sign in with a password. |
| `GET` | `/login/{factor}/options` | `keyring.login.options` | Options for signing in without a username (passkeys). |
| `POST` | `/login/{factor}` | `keyring.login.factor` | Sign in with another primary factor (passkeys). |
| `GET` | `/login/challenge/{factor?}` | `keyring.login.challenge` | The challenge page. |
| `POST` | `/login/challenge/{factor}` | `keyring.login.verify` | Verify the next factor. |
| `POST` | `/login/challenge/{factor}/send` | `keyring.login.send` | Send a code (email codes). |
| `GET` | `/register` | `register` | The registration page. |
| `POST` | `/register` | `register.store` | Create an account and sign in. Uses the `keyring` rate limiter. |
| `POST` | `/logout` | `logout` | Sign out. |

The login and registration routes are for guests only, and `/logout` needs `auth:{guard}`. The registration routes exist only when the `registration` feature is on. The `keyring` rate limiter allows 6 a minute by default; see [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits).

The routes that spend session state (`POST /login`, `POST /login/{factor}` and the challenge's verify and send routes) take Laravel's session lock with `->block()`, so parallel requests in one session wait their turn instead of spending the same state twice. Your cache store must support locks.

A factor key that isn't registered gives a `404` on every route that takes one.

## Signing In With a Password

Post the username and password to `/login`:

| Field | |
|---|---|
| `email` (or your `username` attribute) | Required. Trimmed and lowercased before the lookup (see [`normalizeUsernamesUsing()`](#finding-the-user)). |
| `password` | Required. |
| `remember` | Optional boolean, for Laravel's "remember me" cookie. |

A wrong password and an unknown account produce the same error, on the username field, using Laravel's `auth.failed` message. Both take the same time.

### Finding the User

By default Keyring looks the user up by the `username` attribute, trimmed and lowercased. Change either in your `KeyringServiceProvider`:

```php
use App\Models\User;
use Illuminate\Http\Request;

// Sign in with an email address or a username, and never as a banned user.
Keyring::findUsersUsing(fn (Request $request) => User::query()
    ->where(fn ($query) => $query->where('email', $request->email)->orWhere('username', $request->email))
    ->where('banned', false)
    ->first());

// Keep usernames' case (for lookups, rate limits, email changes and reservations).
Keyring::normalizeUsernamesUsing(fn (string $username) => trim($username));
```

Whether a lookup cares about case also depends on your database: MySQL's default collations ignore it, while PostgreSQL and SQLite don't.

`findUsersUsing()` only finds the user: Keyring still checks the password, and answers a `null` the same way as a wrong password, in the same time. It answers the same way for a user that Keyring's guard wouldn't load back through its provider, like one of another model. The username field's validation still applies; change it with a [pipeline step](#writing-a-step) if you need to.

## Signing In With a Passkey

Passkeys can sign in without a username. The browser asks for options, runs the WebAuthn ceremony, and posts the result:

1. `GET /login/passkey/options` returns WebAuthn request options as JSON, with an empty `allowCredentials`. Keyring keeps the challenge in the session.
2. `POST /login/passkey` with `credential` (the browser's response as JSON) and optionally `remember`.

The same options work for autofill ("conditional UI"), where the browser offers passkeys in the email field. The browser package's `usePasskeyLogin()` does all of this. See [Frontend](frontend.md#signing-in-with-a-passkey).

A passkey sign in still goes through the policy, so a policy like `Requirement::factors(3)` would still ask for more.

Only factors that implement `PrimaryFactor` and return `true` from `startsLogin()` can start a login, and only `DiscoverableFactor`s serve options; other factor keys return a 404. Security keys share the passkey driver but their `startsLogin()` is `false`, so `/login/security-key` and its options route return a 404 too.

## The Challenge Page

`GET /login/challenge` shows the next factor to verify. `GET /login/challenge/{factor}` shows a specific one, if it would help. If there's no pending attempt, the user goes back to the login page.

### Page Props

The page (`challenge` for logins, `confirm` for step-up) receives:

```json
{
  "purpose": "login",
  "factor": "security-key",
  "authenticator": { "factor": "security-key", "id": "01JC3...", "name": "Work key" },
  "challenge": { "options": { "challenge": "...", "rpId": "example.com", "allowCredentials": [] } },
  "alternatives": [
    { "factor": "totp", "id": "01JC4...", "name": "Authenticator app" },
    { "factor": "recovery", "id": "01JC5...", "name": "Recovery codes", "remaining": 7 }
  ],
  "canTrustDevice": true,
  "expiresAt": "2026-11-08T14:05:00+00:00"
}
```

| Prop | |
|---|---|
| `purpose` | `login` or `confirm`. |
| `factor` | The key of the factor to verify now. |
| `authenticator` | How the factor presents this authenticator. Always `factor`, `id` and `name`. `id` is `null` for the password. Email codes add `hint`, a masked address like `t•••@example.com`. Recovery codes add `remaining`. |
| `challenge` | Factor-specific props. See below. |
| `alternatives` | The user's other authenticators that would help, for "try another way". Same shape as `authenticator`. |
| `canTrustDevice` | Whether to show "don't ask again on this device". `true` for logins when `devices.trust_for` isn't `null`. |
| `expiresAt` | When the pending attempt expires, ISO 8601. |

`challenge` for the built-in factors:

| Factor | `challenge` |
|---|---|
| `password`, `totp`, `recovery` | `[]` |
| `email-code` | `length` (digits), `sent` (whether a code has been sent) and `expiresAt` (the code's expiry, or `null`). |
| `passkey`, `security-key` | `options`: WebAuthn request options for the browser. |

Alternatives only include authenticators that bring the user closer to the requirement. After a password, another password isn't offered; with [no downgrade](policies.md#no-downgrade), only passkeys and security keys are.

### Choosing an Authenticator

Without a factor in the URL, the page shows the user's default authenticator if it would help, otherwise the first useful one by priority. To pick one authenticator of a factor, add `?authenticator={id}`:

```
GET /login/challenge/security-key?authenticator=01JC3...
```

Keyring remembers which authenticator the page showed for each factor.

### Verifying

Post the proof to `POST /login/challenge/{factor}`:

| Field | Used by |
|---|---|
| `password` | `password` |
| `code` | `totp`, `email-code`, `recovery` and most custom factors. |
| `credential` | `passkey`, `security-key`: the browser's WebAuthn response, as an object or a JSON string. |
| `authenticator` | Optional. The authenticator ID. Defaults to the one the page showed, or the only one of that factor. |
| `trust` | Optional boolean. Trust this device for `devices.trust_for`, once this login has verified two categories. |

For WebAuthn, the browser may answer with any of the user's keys of that factor, not just the one shown, and Keyring accepts it.

Wrong proofs fail with `keyring::keyring.invalid` on the factor's field (`password`, `code` or `credential`). A wrong code keeps its guess count, so reloading doesn't reset it.

### Sending Codes

Factors that send codes only send when asked:

```
POST /login/challenge/email-code/send
```

Viewing or prefetching the page never sends anything. Each pending attempt can send three codes per 10 minutes; a fourth gets a `429` with Laravel's `auth.throttle` message on `code`. A new code replaces the previous one, and a code only verifies the authenticator it was sent to. The response is a [status response](#status-responses) with `code-sent`.

## Finishing the Login

When the requirement is met, Keyring:

1. signs the user into the guard (with "remember me" if it was ticked),
2. regenerates the session ID, destroying the old one,
3. records what they proved, for [step-up](step-up.md),
4. recognises or registers the [device](devices-and-sessions.md), and registers the session,
5. dispatches `Keyring\Events\Authenticated`,
6. flashes `keyring.alerts` for anything suspicious since their last sign in (see ["Was This You?" Alerts](security-log-and-emails.md#was-this-you-alerts)),
7. dispatches `NewDeviceSignedIn` if the device is new,
8. redirects to the intended URL, or `home`.

## Registration

`POST /register` passes the whole request to your `CreatesNewUsers` action (published to `app/Actions/Keyring/CreateNewUser.php` and registered with `Keyring::createUsersUsing()`). The action validates and returns the new user. Keyring then dispatches Laravel's `Registered` event and signs the user in, counting the password they just chose as proved. It doesn't consult the policy, since the user has no other factors yet.

To leave new users signed out, for example until they verify their email or an admin approves them, pass `false` or a callback to `signInAfterRegistering()`. They're sent to the login page with the `registered` status:

```php
Keyring::signInAfterRegistering(false);
Keyring::signInAfterRegistering(fn (User $user, Request $request) => ! $user->needs_approval);
```

The answer comes from `RegisterResponse`, which by default behaves like `AuthenticatedResponse`. Swap it to send new users somewhere else, like onboarding. See [Responses](#responses).

The published action validates `name`, `email`, `password` and `password_confirmation` (with `PasswordRules::for()`, see [Password Rules](protected-changes.md#password-rules)). Change it to fit your app.

## Signing Out

`POST /logout` revokes the registered session, signs the user out, forgets what they proved, and invalidates the session. JSON clients get `204 No Content`; others are redirected to `/`.

The response also sends `Clear-Site-Data: "cache", "storage"`. It leaves cookies alone so the device cookie survives, and the next sign in isn't treated as a new device.

To sign the current user out the same way from your own code, call `Keyring\Login\SignIn::out()`. It returns the user who was signed out, or `null`, and doesn't dispatch `LoggedOut`:

```php
use Keyring\Login\SignIn;

app(SignIn::class)->out($request);
```

## The Verification Pipeline

Every verification, at login or step-up, goes through one pipeline of steps:

| Step | Does |
|---|---|
| `EnsureNotThrottled` | Checks the factor's rate limits, counts the attempt, and locks out repeated failures. See [Rate Limiting](security.md#rate-limiting). |
| `VerifyFactor` | Validates the request, identifies the user for primary factors, and checks the proof inside the timebox. Stops the pipeline on failure. |
| `ResolveDevice` | Notes the device this attempt comes from, and the `trust` checkbox. |
| `AssessRisk` | Runs the [risk signals](risk.md) once per login and acts on them. Skipped for step-up. |
| `DetermineRequirement` | Asks the policy what's needed. |
| `CompleteAttempt` | Signs the user in, or confirms them, when the requirement is met. Otherwise regenerates the session ID and saves the attempt for the challenge page. |

The steps live in `Keyring\Pipeline\Steps\`.

### Customising the Steps

```php
use App\Keyring\BlockSanctionedCountries;
use App\Keyring\MyRiskStep;
use Keyring\Facades\Keyring;
use Keyring\Pipeline\Steps;
use Keyring\Pipeline\Steps\AssessRisk;
use Keyring\Pipeline\Steps\ResolveDevice;

Keyring::pipeline(fn (Steps $steps) => $steps
    ->after(ResolveDevice::class, BlockSanctionedCountries::class)
    ->replace(AssessRisk::class, MyRiskStep::class));
```

`Steps` has `before()`, `after()`, `replace()` and `remove()`. `before()` and `after()` take any number of steps. Each throws an `InvalidArgumentException` if the step you name isn't in the pipeline. You can call `Keyring::pipeline()` more than once; the callbacks run in order.

### Writing a Step

A step is a class with a `handle()` method that receives a `Keyring\Pipeline\Context` and the next step. Steps are resolved from the container, so you can inject dependencies:

```php
namespace App\Keyring;

use Closure;
use Keyring\Devices\Location;
use Keyring\Enums\Purpose;
use Keyring\Pipeline\Context;

class BlockSanctionedCountries
{
    public function handle(Context $context, Closure $next): Context
    {
        $country = Location::of($context->request)['country'] ?? null;

        if ($context->purpose === Purpose::Login && in_array($country, config('app.blocked_countries'), true)) {
            return $context->fail();
        }

        return $next($context);
    }
}
```

The context holds:

| | |
|---|---|
| `$context->request` | The request. |
| `$context->purpose` | `Purpose::Login` or `Purpose::Confirm`. |
| `$context->factor` | The factor being verified. |
| `$context->attempt` | The pending `Attempt`. |
| `$context->authenticator` | The authenticator being verified. |
| `$context->verification` | The `Verification`, once `VerifyFactor` has passed. |
| `$context->identifying` | Whether this request also identifies the user (the first factor of a login). |
| `$context->outcome` | The `Keyring\Pipeline\Outcome`, set by `CompleteAttempt` or by a failure. |

`Location::of($request)` asks the configured [locator](devices-and-sessions.md#locations) once per request and remembers the answer, so steps, signals and device tracking share one lookup.

Return `$context->fail()` to refuse with the same generic error as a wrong password, or `$context->lockout($seconds)` to answer as rate limited. A failure counts towards the rate limits like a wrong password.

Where you put a step matters. Before `VerifyFactor`, the first factor of a login has no attempt or authenticator yet (`$context->attempt` is `null`). After `VerifyFactor`, steps only run when the proof was right, and the attempt is always set.

## Responses

Each outcome is answered by a response class, bound to a contract in `Keyring\Contracts\Responses`:

| Contract | When | Default |
|---|---|---|
| `AuthenticatedResponse` | The login or confirmation is complete. | Redirect to the intended URL or `home`. JSON: `{"status": "authenticated", "redirect": "..."}`. |
| `ChallengeResponse` | Another factor is needed. | Redirect to the challenge page. JSON: `202` with `{"status": "challenge", "redirect": "..."}`. |
| `FailedResponse` | The proof was wrong or the user wasn't found. | A validation error: `auth.failed` on the username field when starting a login, otherwise `keyring::keyring.invalid` on the factor's field. |
| `LockoutResponse` | Too many attempts. | A `429` validation error with Laravel's `auth.throttle` message. |
| `LogoutResponse` | The user signed out. | Redirect to `/`. JSON: `204`. Both send `Clear-Site-Data`. |
| `RegisterResponse` | A new user registered and was signed in. | The same as `AuthenticatedResponse`. |
| `StatusResponse` | Every other action: a code sent, a password changed, a device signed out... | See [Status Responses](#status-responses). |

"JSON" here means the request expects JSON and isn't an Inertia request. Inertia visits get redirects, like normal page visits.

Swap a response with `Keyring::respondWith()`:

```php
use App\Http\Responses\WelcomeBack;
use Keyring\Contracts\Responses\AuthenticatedResponse;

Keyring::respondWith(AuthenticatedResponse::class, WelcomeBack::class);
```

Your class must implement the contract. After a verification, responses are built with the pipeline's context, so you can accept it in the constructor:

```php
use Keyring\Contracts\Responses\AuthenticatedResponse;
use Keyring\Enums\Purpose;
use Keyring\Pipeline\Context;

class WelcomeBack implements AuthenticatedResponse
{
    public function __construct(protected ?Context $context = null) {}

    public function toResponse($request)
    {
        return $this->context?->purpose === Purpose::Confirm
            ? redirect()->intended(config('keyring.home'))
            : redirect()->intended('/welcome-back');
    }
}
```

`LogoutResponse` and `RegisterResponse` are never given a context.

`respondWith()` also accepts a closure, which is bound in the container like any other binding.

### Status Responses

Every action that isn't a sign in or confirmation answers through `StatusResponse`. It's built with three arguments:

| Argument | |
|---|---|
| `status` | A slug such as `password-updated` or `device-revoked`. |
| `data` | Extra data, such as the new authenticator. Often empty. |
| `redirect` | Where to go instead of back, or `null`. |

JSON clients get the slug, its translated message, the redirect (when there is one) and the data, side by side:

```json
{
  "status": "authenticator-updated",
  "message": "Sign-in method updated.",
  "authenticator": { "factor": "totp", "id": "01JC4...", "name": "Work phone" }
}
```

Other requests are redirected (back, or to `redirect`) with the slug flashed as `status`, and any data flashed as `keyring.result`, for example `session('keyring.result.recoveryCodes')`.

The messages live in `lang/en/status.php`, as `keyring::status.{slug}`. The pages Keyring renders that show a status (`login`, `forgot-password` and `verify-email`) receive the translated message as their `status` prop, not the slug. The slugs are:

`authenticator-added`, `authenticator-removed`, `authenticator-updated`, `code-sent`, `device-reported`, `device-revoked`, `email-change-cancelled`, `email-change-confirmed`, `email-change-invalid`, `email-change-requested`, `email-change-reverted`, `email-changed`, `enroll-first`, `enrollment-started`, `password-reset`, `password-updated`, `registered`, `reset-link-sent`, `sessions-revoked`, `signed-out` and `verification-link-sent`.

Swap it like the others. Your class receives the same named arguments:

```php
use Keyring\Contracts\Responses\StatusResponse;

Keyring::respondWith(StatusResponse::class, MyStatusResponse::class);
```

## Pages

Keyring renders these pages:

| Name | Props |
|---|---|
| `login` | `canResetPassword`, `canRegister`, `status` (a translated message) |
| `challenge` | See [Page Props](#page-props). Used for logins. |
| `confirm` | The same props, with `purpose: "confirm"`. Used for step-up. |
| `register` | none. The published action expects `name`, `email`, `password` and `password_confirmation`. |
| `forgot-password` | `status` (a translated message) |
| `reset-password` | `token`, `email` |
| `verify-email` | `status` (a translated message) |
| `email-change` | `action` (`confirm` or `revert`) and `url` (where its button posts). See [Protected Changes](protected-changes.md#the-emailed-links). |
| `device-report` | `device` (a description) and `url` (where its button posts). See [The "This Wasn't Me" Link](devices-and-sessions.md#the-this-wasnt-me-link). |

With Inertia installed, each renders the component `auth/{name}`, such as `auth/login`. Without Inertia, Keyring renders the Blade view `auth.{name}`, such as `resources/views/auth/login.blade.php`, with the props as view data. Keyring doesn't ship Blade views, so you write them. Until you do, the page throws a `Keyring\Exceptions\MissingPage` exception naming the view to create and the data it receives.

Change the component for a page with `Keyring::page()`:

```php
Keyring::page('challenge', 'Auth/TwoFactor');
```

Or pass a closure that receives the props and returns a response:

```php
Keyring::page('login', fn (array $props) => response()->view('marketing.login', $props));
```

A closure can return anything a route can (a response, a view or a string).

`challenge` and `confirm` are separate pages, so overriding `challenge` with `Keyring::page()` doesn't change step-up; override `confirm` too. A `confirm` page can simply render your `challenge` page with its props.

## Events

All in `Keyring\Events`:

| Event | When | Properties |
|---|---|---|
| `Attempting` | A verification starts. | `request`, `factor` (key), `purpose` |
| `FactorChallenged` | The challenge page shows a factor. | `attempt`, `authenticator` |
| `FactorVerified` | A factor's proof was right. | `attempt`, `authenticator`, `verification` |
| `FactorFailed` | A factor's proof was wrong, or the user wasn't found. | `attempt` (nullable), `authenticator` (nullable), `factor`, `request` |
| `Lockout` | A rate limit was hit. | `request`, `factor`, `retryAfter` |
| `Authenticated` | A login completed. | `user`, `attempt`, `device` |
| `Confirmed` | A step-up completed. | `user`, `attempt` |
| `LoggedOut` | The user signed out. | `user` |
| `SessionEnded` | Keyring signed a session out on its own: revoked, timed out, or ended by a risk response. | `user`, `reason` |

Laravel's own `Login`, `Logout` and `Registered` events still fire, because Keyring signs users in and out through the guard. Like Fortify, Keyring also dispatches Laravel's other auth events next to its own, so listeners and packages built for them keep working:

| Laravel event | Dispatched with |
|---|---|
| `Illuminate\Auth\Events\Failed` | `FactorFailed`. Its credentials hold only the username field, never the password or code. |
| `Illuminate\Auth\Events\Lockout` | `Lockout`. |
| `Illuminate\Auth\Events\PasswordReset` | Keyring's `PasswordReset`. |
