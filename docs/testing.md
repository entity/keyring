# Testing

- [Introduction](#introduction)
- [Setting Up](#setting-up)
- [Acting at an Assurance Level](#acting-at-an-assurance-level)
- [Acting With Real Authenticators](#acting-with-real-authenticators)
- [Faking Factors](#faking-factors)
- [Factories](#factories)
- [Virtual Authenticators](#virtual-authenticators)
- [The Conformance Suite](#the-conformance-suite)

## Introduction

Keyring ships helpers in `Keyring\Testing` so your tests can exercise your app's rules (who needs what, which routes need step-up) without real codes, signatures or waiting.

## Setting Up

A few settings keep tests fast and offline. In your base `TestCase`:

```php
use Keyring\Testing\InteractsWithKeyring;

abstract class TestCase extends BaseTestCase
{
    use InteractsWithKeyring;
}
```

New passwords are only checked against Have I Been Pwned in production, so tests make no network calls. See [Passwords](configuration.md#passwords).

`InteractsWithKeyring` also swaps in an instant timebox for every test that uses it, so failed factor checks don't wait the usual 250ms. Tests without the trait wait the full `timebox` on every failed verification.

## Acting at an Assurance Level

`InteractsWithKeyring` adds methods for signed-in tests, and one for reading errors:

```php
use Keyring\Enums\Assurance;

$this->actingAs($user)->withAssurance(Assurance::AAL2)->get('/billing')->assertOk();

$this->actingAs($user)->freshAt(now()->subHour())->deleteJson('/account')->assertStatus(423);
```

- `withAssurance($level)` pretends the session proved enough to reach that level: a password for AAL1, a password and a TOTP code for AAL2, a security key for AAL3. `Assurance::None` proves nothing.
- `freshAt($time)` pretends those verifications happened at that time, for [`keyring.fresh`](step-up.md#fresh-verification). Without it, they happen now.

You can chain both, in either order. The level defaults to AAL1, so `freshAt()` alone gives a password verification at that time.

A plain `actingAs($user)` proves nothing, so routes behind `keyring.fresh`, including Keyring's own routes for managing sign-in methods, answer `423`. Add `withAssurance()` for those:

```php
$this->actingAs($user)->withAssurance(Assurance::AAL1)
    ->postJson(route('keyring.authenticators.store', 'totp'))
    ->assertOk();
```

`sessionErrors()` returns the validation errors the last request flashed, as a `MessageBag`. Use it rather than `session('errors')`, which is a plain array right after a request when the session is serialized as JSON, the default in new Laravel apps:

```php
$this->post('/login', ['email' => $user->email, 'password' => 'wrong']);

expect($this->sessionErrors()->first('email'))->toBe(__('auth.failed'));
```

The `423` only comes back for JSON requests. A plain `delete()` that needs step-up is redirected to the confirm page instead:

```php
$this->actingAs($user)->freshAt(now()->subHour())
    ->delete('/account')
    ->assertRedirect(route('keyring.confirm.challenge'));
```

## Acting With Real Authenticators

`withAssurance()` pretends, so its verifications aren't tied to any authenticator. Code that looks up the authenticator behind a verification, such as the [email change](protected-changes.md#confirming) check for an established second factor, won't find one. For that, say which of the user's authenticators the session verified:

```php
use Keyring\Models\Authenticator;

// Added yesterday, so it's older than the session.
$totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create(['created_at' => now()->subDay()]);

$this->actingAs($user)->verifiedWith($totp)->post('/user/email', ['email' => 'new@example.com']);
```

`verifiedWith(...$authenticators)` pretends the session verified the password and each authenticator you pass. The level is whatever those reach (a password and an authenticator app is AAL2), so it replaces `withAssurance()`. `freshAt()` chains with it as before.

## Faking Factors

`Keyring::fake()` decides factor checks without real proofs:

```php
use Keyring\Facades\Keyring;

Keyring::fake()->pass('passkey', 'totp')->fail('email-code');
```

- Passed factors verify with whatever is posted, even nothing. Their validation rules are skipped.
- Failed factors always fail.
- Factors you don't name are checked for real.

Identifying the user still happens for real: posting an unknown email to `/login` fails even when `password` passes. Rate limiting, devices, risk and the policy all run as normal.

```php
Keyring::fake()->pass('totp');

$this->post('/login', ['email' => $user->email, 'password' => 'password'])
    ->assertRedirect(route('keyring.login.challenge'));

$this->post(route('keyring.login.verify', 'totp'))->assertRedirect('/dashboard');
```

The fake also notes every factor check made once the account is known, faked or real, so a test can assert what a request asked for:

```php
$fake = Keyring::fake()->pass('totp');

// ...

$fake->assertVerified('totp');
$fake->assertFailed('password', times: 2);
$fake->assertNotChecked('recovery');
```

| Method | Asserts |
|---|---|
| `assertVerified($factor, $times = null)` | The factor was checked and verified, that many times if given. |
| `assertFailed($factor, $times = null)` | The factor was checked and failed, that many times if given. |
| `assertNotChecked($factor)` | The factor was never checked. |
| `assertNothingChecked()` | No factor was checked. |

`Keyring::fake()` throws a `LogicException` when the app environment is `production`, and nothing bound in the container by hand fakes a check there. Other environments can use it, so a browser suite running against `local` or `staging` keeps working.

## Factories

`Keyring\Models\Authenticator` has a factory. Attach authenticators to a user through the `authenticatable` relationship:

```php
use Keyring\Models\Authenticator;

Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
Authenticator::factory()->securityKey()->default()->for($user, 'authenticatable')->create();
```

| State | Creates |
|---|---|
| `totp($secret = null)` | An authenticator app with a random (or the given) secret. This is also the default state. |
| `recoveryCodes($codes = ['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa', 'bbbb-bbbb-bbbb-bbbb-bbbb-bbbb', 'cccc-cccc-cccc-cccc-cccc-cccc'])` | A set of recovery codes that accepts the given codes. Each must be in the form Keyring makes them, 24 base32 characters (`a`-`z` and `2`-`7`), with or without dashes: anything else throws an `InvalidArgumentException`. |
| `emailCode()` | Email codes. |
| `passkey($synced = true)` | A user-verified passkey, synced unless you pass `false`. Only one that isn't synced reaches AAL3. |
| `securityKey($userVerified = false)` | A security key. |
| `attested($aaguid, $type = 'basic')` | Add to either of those: a key whose model was checked by attestation. |
| `default()` | Marks it as the default. |
| `unconfirmed()` | Not yet confirmed, so it doesn't count. |

`totpCode()`, from `InteractsWithKeyring`, gives the code an authenticator app would show right now. It takes a TOTP authenticator or a secret:

```php
$totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

$this->post(route('keyring.login.verify', 'totp'), ['code' => $this->totpCode($totp)]);
```

Each code works once, as in real life, so enrolling an app and then signing in with it in the same 30 seconds fails. Keyring keeps TOTP time on Laravel's clock, so `$this->travel(30)->seconds()` moves on to the next code, or pass a later step: `$this->totpCode($totp, step: 1)`.

The `passkey()` and `securityKey()` states have no real public key, so they only verify with `Keyring::fake()`. For real WebAuthn responses, enroll a virtual authenticator instead.

## Virtual Authenticators

`Keyring\Testing\VirtualAuthenticator` is a software WebAuthn key. It answers the options Keyring gives the browser with real, signed responses, so the whole ceremony runs without a browser or hardware key:

```php
use Keyring\Testing\VirtualAuthenticator;

$key = new VirtualAuthenticator;

// Register it.
$this->actingAs($user)->withAssurance(Assurance::AAL1);
$options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');
$this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();
$this->post('/logout');

// Sign in with it, without a username.
$options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
$this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
    ->assertRedirect('/dashboard');
```

For a key used on the challenge page, read the options from the page props. With Inertia, send the `X-Inertia` header to get the page as JSON:

```php
$options = $this->withHeaders(['X-Inertia' => 'true'])
    ->get(route('keyring.login.challenge'))
    ->json('props.challenge.options');

$this->flushHeaders();

$this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)]);
```

The constructor options:

| Option | Default | |
|---|---|---|
| `origin` | Your `APP_URL`'s origin | The origin it claims to be on. By default, the first origin Keyring accepts. |
| `userVerification` | `true` | Whether it reports verifying the user. Use `false` for a basic security key. |
| `aaguid` | 16 zero bytes | The AAGUID it reports, as raw bytes. |
| `algorithm` | `ES256` | `ES256` or `EdDSA`. |
| `synced` | `false` | Whether it reports being a passkey that syncs between devices. |

`VirtualAuthenticator::eddsa()` makes a key that signs with Ed25519 instead of P-256. It needs PHP's `sodium` extension, as does Keyring's support for Ed25519 keys.

`$key->assert($options, $origin)` can answer from another origin, to test that Keyring rejects it. `$key->rewindCounter()` makes the next response reuse an old counter, as a cloned key would.

### Keys That Attest

A factor that [requires attestation](passkeys.md#requiring-attestation) refuses a plain virtual authenticator, as it would any key that doesn't say who made it. `Keyring\Testing\VirtualManufacturer` is a maker of keys with a throwaway root certificate. Trust its root, and its keys attest the way hardware does:

```php
use Keyring\Testing\VirtualManufacturer;

$maker = new VirtualManufacturer;
config(['keyring.webauthn.attestation_roots' => [$maker->root]]);

$key = $maker->key('2fc0579f-8113-47ea-b116-bb5a8db9202a');

$options = $this->postJson(route('keyring.authenticators.store', 'security-key'))->json('enrollment.options');
$this->postJson(route('keyring.authenticators.confirm', 'security-key'), ['credential' => $key->register($options)])->assertOk();
```

`key()` takes the model's AAGUID, the format (`packed` by default, or `fido-u2f`, which has no AAGUID) and whether the key verifies the user. `new VirtualManufacturer(intermediate: true)` signs its keys' certificates with an intermediate certificate instead of the root, and `days:` sets how long its certificates last.

To check that your app turns keys away, use a key from a second `VirtualManufacturer` you don't trust, or `new VirtualAuthenticator()->selfAttested()`, which attests with its own key pair.

## The Conformance Suite

`Keyring\Testing\KeyringConformance` is a set of tests that check your setup (policy, factors, swapped responses, pipeline changes) still keeps Keyring's guarantees. Checks for features that are off are skipped, with the reason, so a skipped check is something your setup doesn't use, not a pass. Add it to a test class and tell it how to make a user:

```php
namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Keyring\Testing\KeyringConformance;
use Tests\TestCase;

class KeyringConformanceTest extends TestCase
{
    use KeyringConformance, RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        Notification::fake();
    }

    protected function keyringUser(): User
    {
        return User::factory()->create(['password' => 'password', 'email_verified_at' => now()]);
    }
}
```

`keyringUser()` must return a user whose password is `password` (override `keyringPassword()` to change it), whose email is verified, and who has no extra factors. Faking notifications stops the email code factor from sending real mail when the suite begins enrolling it.

The suite checks that:

- a correct password either signs in or leads to the challenge page,
- a wrong password and an unknown account give the same error,
- protected attributes can't change outside Keyring's flows,
- changing sign-in methods needs a fresh verification,
- every enrollable factor can begin enrolling,
- signing out revokes the registered session,
- every route that uses the `auth` middleware for Keyring's guard also runs [`keyring.session`](devices-and-sessions.md#the-session-middleware), so a session that was revoked or timed out doesn't keep working there,
- passwords of 64 characters are allowed: `passwords.max` is at least 64, and the hasher isn't bcrypt, which stops at 72 bytes,
- no mandatory pipeline step was removed or replaced with `dangerouslyRemove()` or `dangerouslyReplace()`.

If you take out a [mandatory step](sign-in-flow.md#mandatory-steps) on purpose, return its class from `keyringAcknowledgedDangerousSteps()` in your test class.

The route check reads your app's routes as they're registered: `auth:{guard}` by name, plain `auth` when Keyring's guard is the default, and `auth:sanctum` on routes with Sanctum's `statefulApi()`, where a single-page app is signed in by its session. It fails with the URIs that are missing the middleware. Add `keyring.session` to their group, or, for a route you leave unchecked on purpose, return its URI from `keyringAcknowledgedUncheckedRoutes()`:

```php
protected function keyringAcknowledgedUncheckedRoutes(): array
{
    return ['internal/health'];
}
```

A new Laravel app hashes with bcrypt, so the password length check fails until you set `HASH_DRIVER=argon2id` (see [Passwords](configuration.md#passwords)). If your tests run on bcrypt for speed and production doesn't, set the driver for this test class. To keep bcrypt and its limit, say so:

```php
protected function keyringAcknowledgesBcryptLimit(): bool
{
    return true;
}
```

`KeyringConformance` includes `InteractsWithKeyring`, and its tests are ordinary `test_*` methods.
