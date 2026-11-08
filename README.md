# Keyring

Factor-driven authentication for Laravel. It feels like Fortify, but it's built to be extended.

Fortify keeps 2FA in three columns on `users`. That gives one TOTP per user, and everything else gets bolted on. Keyring treats every way of signing in as a **factor** behind one contract. A user holds as many **authenticators** as they like, and one **policy** decides what they must prove.

- **Many authenticators per user:** two authenticator apps, three security keys, a passkey. One is the default, and the user can "try another way".
- **Factors are drivers:** password, TOTP, passkeys, security keys, email codes and recovery codes all share one contract. You can add SMS, push or anything else without new routes, controllers or tables.
- **Passkeys and security keys work as either factor:** one WebAuthn driver with two profiles. Inherence only counts when the key actually verified the user.
- **Devices and sessions are built in:** new-device events, "this wasn't me" links, a sessions list, and "sign out everywhere else". It works with **any session driver** (database, Redis, file, cookie).
- **Step-up:** `keyring:aal2` and `keyring.fresh:15m` middleware. A passkey or code counts, not just the password, and users with a second factor must use it.
- **Protected account changes:** `email` and `password` can only change through Keyring's flows (OWASP). Email changes are confirmed from both addresses and can be reverted.
- **Risk signals:** new device, new country, impossible travel, a session cookie showing up in another browser, repeated failures. Each level maps to an action.
- **A security log and opt-in security emails.**
- **Headless:** Inertia pages by default, swappable responses, published actions. `keyring:install --inertia=vue|react` gives you working pages.

> Work in progress: not tagged or production-tested yet.

## Requirements

- PHP 8.5+
- Laravel 13+
- Inertia v3 (optional; without it, Keyring renders Blade views named `auth.*`)

## Installation

```bash
composer require entity/keyring
php artisan keyring:install --inertia=vue   # or react, or leave it off for headless
php artisan migrate
```

Add the trait to your user model:

```php
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable
{
    use HasKeyring;
}
```

Coming from Fortify? `php artisan keyring:import fortify` copies `two_factor_*` columns and the `laravel/passkeys` table into Keyring. Users keep their authenticator apps, recovery codes and passkeys.

For the frontend helpers:

```bash
npm install @entity/keyring
```

## Configuring factors and the policy

`keyring:install` publishes `app/Providers/KeyringServiceProvider.php`:

```php
Keyring::factors([
    Password::class,
    WebAuthn::passkeys(),
    WebAuthn::securityKeys(),
    Totp::class,
    EmailCode::class,
    RecoveryCodes::class,
]);

Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());
```

A **requirement** counts *distinct categories* (knowledge, possession, inherence), so a password plus a PIN is still one factor.

| | Means |
|---|---|
| `Requirement::aal1()` | Any one factor. |
| `Requirement::aal2()` | Two categories. A user-verified passkey covers this on its own. |
| `Requirement::aal3()` | Two categories, including a phishing-resistant key. |
| `->including(Category::Possession)` | That category must be among those verified. |
| `->phishingResistant()` | At least one WebAuthn verification. |
| `->ifEnrolled()` | Only ask for this when the user has set up enough factors. This is Fortify's behaviour. |
| `->noDowngrade()` | Users with a passkey or security key must use one, and weaker fallbacks aren't offered. |

Decide per user and attempt with a closure:

```php
Keyring::require(fn (User $user, Attempt $attempt) => match (true) {
    $user->is_admin => Requirement::aal2()->phishingResistant(),
    $attempt->device()?->isTrusted() === true => Requirement::aal1(),
    $attempt->risk?->isElevated() === true => Requirement::aal2(),
    default => Requirement::aal2()->ifEnrolled(),
});
```

## The sign-in flow

1. `POST /login` (or `POST /login/passkey` for usernameless passkeys) verifies the first factor.
2. If the policy needs more, the user is redirected to `GET /login/challenge/{factor?}`. The page receives:

   ```json
   {
     "purpose": "login",
     "factor": "security-key",
     "authenticator": { "factor": "security-key", "id": "01J…", "name": "YubiKey 5C" },
     "challenge": { "options": { "...": "WebAuthn request options" } },
     "alternatives": [
       { "factor": "totp", "id": "01J…", "name": "1Password" },
       { "factor": "recovery", "id": "01J…", "name": "Recovery codes", "remaining": 7 }
     ],
     "canTrustDevice": true,
     "expiresAt": "2026-11-08T14:05:00+00:00"
   }
   ```

3. `POST /login/challenge/{factor}` verifies the next factor. Code factors only send a code on `POST /login/challenge/{factor}/send`, so prefetching the page never sends anything.

Every verification goes through one pipeline. You can change it:

```php
Keyring::pipeline(fn (Steps $steps) => $steps
    ->after(ResolveDevice::class, BlockSanctionedCountries::class)
    ->replace(AssessRisk::class, MyRiskStep::class));
```

The default steps are `EnsureNotThrottled`, `VerifyFactor` (timeboxed), `ResolveDevice`, `AssessRisk`, `DetermineRequirement` and `CompleteAttempt`.

Swap any response:

```php
Keyring::respondWith(AuthenticatedResponse::class, MyAuthenticatedResponse::class);
```

Or change which component a page renders:

```php
Keyring::page('challenge', 'Auth/TwoFactor');
```

## Step-up

```php
#[Middleware(['auth', 'keyring:aal2'])]
class BillingController
{
    #[Middleware('keyring.fresh:15m')]
    public function destroy() { /* ... */ }
}
```

- `keyring:aal2` asks for whatever is missing to reach that level.
- `keyring.fresh:15m` asks for a verification within the window. Password-only users confirm with their password. Users who have a second factor must use one, so a stolen session plus a phished password can't add or remove factors. The window is fixed from the moment of verification and doesn't slide with activity.
- Adding a sign-in method needs a verified email address, so someone who registers an address first can't plant a factor that survives the real owner's password reset.

Both use the same challenge page with `purpose: "confirm"`. Confirming also satisfies Laravel's own `password.confirm`.

## Managing authenticators

One set of routes covers every factor. They need a fresh verification by default (`keyring.manage_middleware`).

```
POST   /user/authenticators/{factor}          begin: QR code, WebAuthn options, recovery codes…
POST   /user/authenticators/{factor}/confirm  finish: prove it works
PATCH  /user/authenticators/{id}              rename / make default
DELETE /user/authenticators/{id}              remove (never below what the policy needs)
```

The first extra factor automatically comes with recovery codes. From JavaScript:

```ts
import { enroll, beginEnrollment, confirmEnrollment } from '@entity/keyring'

await enroll('passkey', { name: 'MacBook' })  // runs the browser ceremony for you
const { enrollment } = await beginEnrollment('totp')  // show enrollment.qr
await confirmEnrollment('totp', enrollment, { code })
```

In PHP:

```php
$user->keyring->all();
$user->keyring->default();
$user->keyring->of('security-key');
$user->keyring->has(Category::Possession);
```

## Writing a factor

Code factors only need a key and a way to deliver the code. The base class handles the OWASP rules: random codes, short expiry, single use, limited guesses, a resend replacing the old code, and hashed storage.

```php
class SmsCode extends CodeFactor
{
    public function key(): string { return 'sms'; }

    protected function defaultName(Authenticatable&Model $user): string { return 'Text message'; }

    protected function deliver(Authenticatable&Model $user, Authenticator $authenticator, string $code): void
    {
        $user->notify(new SmsCodeNotification($code));
    }
}

Keyring::factors([..., SmsCode::class]);
```

Anything else implements `Keyring\Contracts\Factor`, plus optionally `PrimaryFactor` (it can start a login), `DiscoverableFactor` (usernameless), `Enrollable` and `SendsCodes`.

## Devices and sessions

Devices are recognised by a long-lived, httpOnly cookie, stored hashed. A trusted device is an input to your policy, never a factor.

```php
Event::listen(function (NewDeviceSignedIn $event) {
    $event->user->notify(new NewSignIn($event->device->description(), $event->revokeUrl()));
});
```

Keyring keeps its own **session registry**, so sessions can be listed and revoked whichever session driver you use:

```php
'sessions' => [
    'driver' => 'database',   // or 'cache' (Redis, Valkey…), or your own via SessionRegistryManager::extend()
    'idle' => null,
    'absolute' => '30d',
    'levels' => ['aal3' => ['idle' => '15m', 'absolute' => '8h']],
],
```

The routes are `GET /user/devices`, `DELETE /user/devices/{id}` and `DELETE /user/devices` (sign out everywhere else). The signed `GET /devices/{id}/report` link is the "this wasn't me" action.

## Protected changes

```php
$user->update(['email' => 'new@example.com']);   // throws ProtectedAttributeException

Keyring::withoutProtection(fn () => $user->update([...]), reason: 'support ticket 42');   // fires ProtectionBypassed
```

- **Email change** (`POST /user/email`):
  - It needs a fresh verification.
  - The new address must confirm. The current address gets a notice with a revert link, and must confirm too unless this session proved a second factor that existed before it signed in.
  - Emailed links open a page with a button; only the button (a POST) changes anything, so mail scanners that open links can't confirm or revert.
  - A change only applies if the address is still the one it was requested from.
  - It never reveals whether the new address belongs to someone else.
  - The revert link signs out every session, closes any later changes, and removes sign-in methods added since the change was requested.
  - Password resets and password changes cancel any change still pending.
- **Password change** (`PUT /user/password`): it needs the current password, applies the OWASP rules and signs out other sessions:
  - at least 8 characters with MFA, 15 without
  - up to 128 characters, rejecting anything bcrypt would truncate
  - breached passwords blocked
- **Password reset:**
  - the same answer for every address
  - links built from `APP_URL`, never the `Host` header
  - `Referrer-Policy: no-referrer`
  - no automatic sign in
  - every session signed out

## Risk

```php
Keyring::risk([NewDevice::class, NewCountry::class, ImpossibleTravel::class, SessionFingerprintChanged::class])
    ->respond(fn (Risk $risk, Checkpoint $at) => match ($risk->level) {
        Level::Low => Action::allow(),
        Level::Medium => Action::stepUp(),
        Level::High => Action::stepUp()->notify(),
        Level::Critical => Action::deny()->revokeAllSessions()->lockFor('1h')->notify(),
    });
```

Signals run at login, and the cheap ones run again on every signed-in request. Bind `Keyring\Contracts\LocatesIps` (MaxMind, your CDN's headers through `HeaderLocator`…) to turn on the location signals. Write your own by implementing `Keyring\Contracts\Signal`.

## Security log and emails

Sign-ins, failures, lockouts, changes and automatic actions go to `keyring_events`. Read them with `Keyring::activity($user)`, and prune with `model:prune`.

After a successful sign-in, anything worth asking about ("someone entered your password but failed the second step") is flashed as `keyring.alerts`. Share it through your Inertia middleware for a "Was this you?" banner.

Security emails are off by default. Turn them all on, or pick the ones you want:

```php
Keyring::notify();
Keyring::notify(['new_device', 'second_factor_failed']);
```

## Testing

```php
use Keyring\Testing\InteractsWithKeyring;

$this->actingAs($user)->withAssurance(Assurance::AAL2)->get('/billing')->assertOk();
$this->actingAs($user)->freshAt(now()->subHour())->delete('/account')->assertStatus(423);

Keyring::fake()->pass('passkey')->fail('totp');

Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
Authenticator::factory()->securityKey()->for($user, 'authenticatable')->create();
```

`Keyring\Testing\VirtualAuthenticator` is a software WebAuthn key that produces real signed responses. Add `Keyring\Testing\KeyringConformance` to a test class to check your setup still keeps Keyring's guarantees.

```bash
composer test   # Pest
composer lint   # Pint
composer analyse   # Larastan
```

## License

MIT
