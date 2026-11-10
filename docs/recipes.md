# Recipes

- [Introduction](#introduction)
- [Locations With stevebauman/location](#locations-with-stevebaumanlocation)
- [Locations From Cloudflare](#locations-from-cloudflare)
- [Emails With Maizzle](#emails-with-maizzle)
- [SMS Codes](#sms-codes)
- [Social Login With Socialite](#social-login-with-socialite)
- [Usernames Instead of Email Addresses](#usernames-instead-of-email-addresses)
- [Links for Apps on Several Domains](#links-for-apps-on-several-domains)
- [Storing Less About Requests](#storing-less-about-requests)
- [Accounts an Admin Approves](#accounts-an-admin-approves)

## Introduction

Worked examples of the hooks in [Extending Keyring](extending.md), with the packages people usually reach for. Each one was run against a real app before it was written down.

The ones that use another package were written against `stevebauman/location` 7.8, `laravel/socialite` 5.31, `laravel/vonage-notification-channel` 3.3 and `@maizzle/framework` 6.3, on Laravel 13. Check their own docs if you're on something newer.

## Locations With stevebauman/location

Keyring shows where a device signed in from, and the [`NewCountry` and `ImpossibleTravel` signals](risk.md) need a location to work. It asks a locator class for one, and [`stevebauman/location`](https://github.com/stevebauman/location) can be that class.

```bash
composer require stevebauman/location
php artisan vendor:publish --provider="Stevebauman\Location\LocationServiceProvider"
```

```php
namespace App\Keyring;

use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;
use Stevebauman\Location\Facades\Location;

class IpLocator implements LocatesIps
{
    public function locate(Request $request): ?array
    {
        $position = Location::get($request->ip());

        if ($position === false || $position->countryCode === null) {
            return null;
        }

        return array_filter([
            'country' => $position->countryCode,
            'region' => $position->regionName,
            'city' => $position->cityName,
            'latitude' => $position->latitude === null ? null : (float) $position->latitude,
            'longitude' => $position->longitude === null ? null : (float) $position->longitude,
        ], fn ($value) => $value !== null);
    }
}
```

Point Keyring at it, turn on devices, and pick the signals:

```php
// config/keyring.php
'devices' => [
    'locator' => App\Keyring\IpLocator::class,
],
```

```php
// KeyringServiceProvider
Keyring::risk()->signals([NewDevice::class, NewCountry::class, ImpossibleTravel::class]);
```

Three things to know:

- **Its default driver calls an API.** Keyring asks the locator at most once per request, and only on requests that need a location, but a sign in then waits on that call. For production, set `location.driver` to its MaxMind driver with a local database file, which answers from disk.
- **It returns a fixed test location until you turn that off.** `LOCATION_TESTING` defaults to `true`, which locates every request at a Google address in the United States. Set `LOCATION_TESTING=false` outside local development.
- **If it throws, the sign in still works.** Keyring treats the location as unknown for that request and reports the exception.

Behind a load balancer, configure Laravel's [trusted proxies](https://laravel.com/docs/requests#configuring-trusted-proxies), or every request has the balancer's address and so the same location.

In tests, `Location::fake()` gives a location without a lookup:

```php
use Stevebauman\Location\Facades\Location;
use Stevebauman\Location\Position;

Location::fake(['*' => Position::make(['countryCode' => 'NL', 'cityName' => 'Amsterdam'])]);
```

## Locations From Cloudflare

If your app is only reachable through Cloudflare, it can tell you where each request came from, with no lookup at all. `Keyring\Devices\HeaderLocator` reads its headers:

```php
// config/keyring.php
'devices' => [
    'locator' => Keyring\Devices\HeaderLocator::class,
],
```

Cloudflare sends `CF-IPCountry` by default. The city, region and coordinates, which impossible travel needs, come with its "Add visitor location headers" managed transform.

Only use this when requests can't reach your app without going through the proxy. Anyone who can reach it directly can send these headers themselves and choose their own location.

For another proxy or CDN, bind the locator with your own header names. See [Locations](devices-and-sessions.md#locations).

## Emails With Maizzle

Every email Keyring sends is a [notification class in your app](security-log-and-emails.md#security-emails), so it can render any template. [Maizzle](https://maizzle.com) builds email-safe HTML from Vue and Tailwind, and can write Blade views.

```bash
npm install -D @maizzle/framework
```

```js
// maizzle.config.js
import { readFileSync, writeFileSync } from 'node:fs';
import { defineConfig } from '@maizzle/framework';

export default defineConfig({
    root: 'resources/emails',
    content: ['./keyring/*.vue'],
    output: { path: 'resources/views/emails/keyring', extension: 'blade.php' },
    plaintext: { destination: 'resources/views/emails/keyring/text', extension: 'blade.php' },
    static: { source: [] },
    css: { inline: true, purge: true },
    // The plain text views print values as they are: they have no markup
    // to protect, and would show the entities Blade's {{ }} writes.
    afterBuild({ files }) {
        for (const file of files.filter((file) => file.includes('/text/'))) {
            writeFileSync(file, readFileSync(file, 'utf8').replace(/\{\{\s*(.+?)\s*\}\}/g, '{!! $1 !!}'));
        }
    },
});
```

```css
/* resources/emails/tailwind.css */
@import "@maizzle/tailwindcss";
```

A template is a Vue file. Whatever changes per email is a Blade variable inside `<Raw>`, which Maizzle passes through untouched:

```vue
<!-- resources/emails/keyring/notice.vue -->
<template>
  <Layout class="bg-slate-100">
    <Container class="max-w-xl p-6">
      <Heading class="text-2xl font-semibold text-slate-900"><Raw>{{ $subject }}</Raw></Heading>
      <Text class="text-base text-slate-600"><Raw>{{ $intro }}</Raw></Text>

      <Raw>@foreach ($details as $detail)</Raw>
      <Text class="m-0 text-sm text-slate-500"><Raw>{{ $detail['label'] }}: {{ $detail['value'] }}</Raw></Text>
      <Raw>@endforeach</Raw>

      <Raw>@isset($actionUrl)</Raw>
      <Button href="{{ $actionUrl }}" class="bg-slate-900 text-white"><Raw>{{ $actionText }}</Raw></Button>
      <Raw>@endisset</Raw>
    </Container>
  </Layout>
</template>
```

`npx maizzle build` writes `notice.blade.php` and `text/notice.blade.php`. The published `SecurityNotice` then returns them, and all ten notices use the one template:

```php
// app/Notifications/Keyring/SecurityNotice.php
public function toMail(object $notifiable): MailMessage
{
    $details = array_filter([__('When') => $this->when, __('Device') => $this->device, __('IP address') => $this->ip]);

    return (new MailMessage)->subject($this->subject())->view(
        ['html' => 'emails.keyring.notice', 'text' => 'emails.keyring.text.notice'],
        [
            'subject' => $this->subject(),
            'intro' => $this->intro(),
            'details' => array_map(fn (string $label, string $value) => ['label' => $label, 'value' => $value], array_keys($details), $details),
            'actionText' => $this->action(),
            'actionUrl' => $this->action() === null ? null : $this->url,
        ],
    );
}
```

Two things that catch people out:

- **Keep `=>` and `>` out of the Blade inside `<Raw>`.** Maizzle writes them as HTML entities, which breaks the directive. Pass a list of `['label' => ..., 'value' => ...]` rather than looping over keys and values, and write `@if ($details !== [])` rather than a count.
- **Blade's `{{ }}` is what keeps the HTML safe.** A key's name is whatever the user typed, and the escaping stops it adding a link to a genuine security email. Don't swap it for `{!! !!}` in the HTML views.

The [example app](https://github.com/entity/keyring-example#emails) has the whole thing: five templates, a shared frame, the four emails a flow needs, and a local page that previews each one.

## SMS Codes

A factor that sends a code extends `Keyring\Factors\CodeFactor`, which handles expiry, guess limits, resending and enrollment. This one sends it by SMS with Laravel's Vonage channel.

```bash
composer require laravel/vonage-notification-channel
```

```php
namespace App\Keyring;

use App\Notifications\SmsVerificationCode;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Notification;
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
        return __('Text message');
    }

    /**
     * The number is asked for when the user adds the factor, and kept
     * encrypted on the authenticator.
     */
    protected function newAuthenticator(Authenticatable&Model $user, Request $request): Authenticator
    {
        $phone = $request->validate(['phone' => ['required', 'string', 'regex:/^\+[1-9]\d{6,14}$/']])['phone'];

        return parent::newAuthenticator($user, $request)->forceFill(['secret' => $phone]);
    }

    /**
     * To the number on the authenticator, not one on the user, so each of a
     * user's phones gets its own codes.
     */
    protected function deliver(Authenticatable&Model $user, Authenticator $authenticator, string $code): void
    {
        Notification::route('vonage', $authenticator->secret)->notify(new SmsVerificationCode($code));
    }

    /**
     * Show which phone a code goes to, without showing the number.
     */
    public function present(Authenticator $authenticator): array
    {
        return [...parent::present($authenticator), 'hint' => '•••• '.substr((string) $authenticator->secret, -2)];
    }
}
```

```php
namespace App\Notifications;

use Illuminate\Notifications\Messages\VonageMessage;
use Illuminate\Notifications\Notification;

class SmsVerificationCode extends Notification
{
    public function __construct(#[\SensitiveParameter] public string $code) {}

    public function via(object $notifiable): array
    {
        return ['vonage'];
    }

    public function toVonage(object $notifiable): VonageMessage
    {
        return (new VonageMessage)->content(__(':code is your :app verification code.', ['code' => $this->code, 'app' => config('app.name')]));
    }
}
```

Register it, and users can add it like any other sign-in method. Your form posts `phone` to `POST /user/authenticators/sms`, then the code to `POST /user/authenticators/sms/confirm`:

```php
Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, SmsCode::class]);
```

Don't queue the notification, so the code arrives while the user waits. Confirming the enrollment proves the number receives codes, and a code only verifies the phone it was sent to.

SMS is a weak second factor: numbers get moved to a new SIM by someone who talks the carrier into it. Offer it next to an authenticator app or passkey, not in their place. Each account can be sent [three codes every ten minutes](configuration.md#pending-logins-timebox-and-rate-limits) by default, which also caps what a stranger can make you spend.

For another provider, only `deliver()` changes: call its SDK there, or route the notification to its channel.

## Social Login With Socialite

A social login is a way to sign in, so in Keyring it's a [factor](factors.md#writing-any-other-factor) that can start a login. Writing it as one means a "Sign in with GitHub" goes through the same pipeline as the login form: rate limits, your policy, risk, devices and sessions. A user with a second factor is still asked for it.

```bash
composer require laravel/socialite
```

Add a `github_id` column to your users (nullable and unique), then the factor:

```php
namespace App\Keyring;

use App\Models\User;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Category;
use Keyring\Factors\Factor;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Laravel\Socialite\Facades\Socialite;
use Throwable;

class GitHub extends Factor implements PrimaryFactor
{
    public function key(): string
    {
        return 'github';
    }

    public function startsLogin(): bool
    {
        return true;
    }

    /**
     * GitHub's answer only comes with the callback that starts a sign in.
     * A challenge or a confirmation has nothing from GitHub to check, so
     * this factor is never offered there.
     */
    public function answersChallenges(): bool
    {
        return false;
    }

    /**
     * It stands in for the password, so it counts as the same kind of proof.
     */
    public function categories(Authenticator $authenticator): array
    {
        return [Category::Knowledge];
    }

    /**
     * Users who have linked a GitHub account have this way to sign in.
     */
    public function authenticators(Authenticatable&Model $user, Collection $stored): Collection
    {
        return filled($user->getAttribute('github_id'))
            ? new Collection([Authenticator::virtual($this, $user, 'GitHub')])
            : new Collection;
    }

    /**
     * Who the callback is for: the user linked to the GitHub account that
     * GitHub says just signed in.
     */
    public function identify(Request $request): ?Authenticator
    {
        try {
            $id = Socialite::driver('github')->user()->getId();
        } catch (Throwable) {
            return null;
        }

        $user = User::query()->where('github_id', $id)->first();

        return $user === null ? null : Authenticator::virtual($this, $user, 'GitHub');
    }

    /**
     * Only called on the callback, straight after identify() found the user
     * GitHub vouched for, so there's nothing more to prove.
     */
    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        return $this->verified($authenticator);
    }

    public function identificationRules(): array
    {
        return [];
    }

    public function rules(): array
    {
        return [];
    }

    /**
     * The login page shows problems on its email field.
     */
    public function errorKey(): string
    {
        return 'email';
    }
}
```

Register it with your other factors, and add the two routes. `Keyring::attempt()` starts a sign in with a factor from a route of your own, and answers as the login form would:

```php
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Keyring\Facades\Keyring;
use Laravel\Socialite\Facades\Socialite;

Route::middleware('guest')->group(function () {
    Route::get('/auth/github', fn () => Socialite::driver('github')->redirect());

    Route::get('/auth/github/callback', function (Request $request) {
        try {
            return Keyring::attempt($request, 'github');
        } catch (ValidationException $e) {
            // A failed form post goes back to the form. This came from
            // GitHub, so send it to the login page instead.
            return to_route('login')->withErrors($e->errors());
        }
    })->block();
});
```

`->block()` takes the session lock, as Keyring's own sign-in routes do.

What this gives you:

- A linked user with no second factor is signed in and sent to `home`.
- A linked user with an authenticator app or passkey is sent to the challenge page first.
- A GitHub account that isn't linked gets the same "these credentials don't match" as a wrong password.
- Attempts count against the per-IP limit, and a [risk lock](risk.md#actions) refuses them, like any other sign in.
- GitHub is never offered on the confirm page. A user is asked for their password or another sign-in method there, and one who only has GitHub signs in again to do anything behind [`keyring.fresh`](step-up.md).

**Match on the provider's ID, never on the email address.** Some providers let an account carry an address its owner hasn't proven, so matching on it would let someone sign in to whoever has that address in your app.

To link an account, send a signed-in user through the same redirect to a second callback that saves the ID. Put it behind `keyring.fresh`, since it adds a way to sign in:

```php
Route::get('/settings/github/callback', function (Request $request) {
    $request->user()->forceFill(['github_id' => Socialite::driver('github')->user()->getId()])->save();

    return to_route('security.edit');
})->middleware(['auth', 'keyring.fresh:15m']);
```

To let people sign up with GitHub, create and link the user in the login callback before calling `Keyring::attempt()`, when no user has that ID yet.

In tests, `Socialite::fake()` stands in for GitHub:

```php
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\User as GitHubUser;

Socialite::fake('github', (new GitHubUser)->map(['id' => '1001']));

$this->get('/auth/github/callback')->assertRedirect('/dashboard');
```

## Usernames Instead of Email Addresses

When users sign in with a handle and have an email address too, tell Keyring which attribute is which:

```php
// config/keyring.php
'username' => 'handle',

'email' => 'email',
```

The login form then posts `handle` and `password`. Password resets, email changes and email codes keep using the address.

Keyring lowercases what's typed before looking the user up, so store handles lowercased, or keep their case with `Keyring::normalizeUsernamesUsing(fn (string $username) => trim($username))`.

To accept either on one field, leave `username` as `email` and find the user yourself:

```php
use App\Models\User;
use Illuminate\Http\Request;

Keyring::findUsersUsing(fn (Request $request) => User::query()
    ->where('email', $request->string('email')->lower()->value())
    ->orWhere('handle', $request->string('email')->lower()->value())
    ->first());
```

Guesses at either one count against the same account, without the sign-in form showing that the two belong together. See [Rate Limiting](security.md#rate-limiting) and [Finding the User](sign-in-flow.md#finding-the-user).

## Links for Apps on Several Domains

Keyring builds every emailed link from `APP_URL`. When each tenant has its own domain, start the links there:

```php
Keyring::linkRootUsing(fn () => tenant()?->url ?? config('app.url'));
```

The callback runs when a link is built, which is while handling the request or in the queued job that sends the email, so read the tenant from wherever your tenancy package keeps it in both.

Return something the server knows. The request's `Host` header is whatever the sender wrote, and a reset link built from it would deliver a real token to their site.

Passkeys are tied to a domain too. Set `webauthn.relying_party.id` and `webauthn.origins` per tenant if each one registers its own. See [Passkeys & Security Keys](passkeys.md#relying-party-and-origins).

## Storing Less About Requests

Keyring keeps the request's IP address on devices, sessions and security log entries, and passes it to security notices. To keep only the network:

```php
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;

// 203.0.113.7 becomes 203.0.113.0
Keyring::recordIpsUsing(fn (Request $request) => IpUtils::anonymize((string) $request->ip()));
```

Or return `null` to keep none. Rate limits and the locator still see the real address, since neither stores it.

How long things are kept is config too:

```php
// config/keyring.php
'security_log' => ['keep_for' => '30d'],

'devices' => ['keep_revoked_for' => '7d', 'keep_unseen_for' => '90d'],

'email_changes' => ['keep_ended_for' => '7d'],
```

`keyring:prune` deletes what's past those, so [schedule it daily](devices-and-sessions.md#pruning). To record nothing at all, leave `Features::securityLog()` and `Features::devices()` off.

## Accounts an Admin Approves

For an app where someone reviews each sign-up, don't let anyone sign in until they're approved:

```php
use App\Models\User;

// Only approved accounts can sign in, however they try: the password, a
// passkey, "remember me". Everyone else gets the same answer as a wrong
// password, and registering sends them to the login page.
Keyring::allowSignInWhen(fn (User $user) => $user->approved_at !== null);
```

Withdrawing an approval signs the account out on its next request. See [Who May Sign In](sign-in-flow.md#who-may-sign-in).

Approval can also be what lets a user add a sign-in method, in place of verifying their email address:

```php
Keyring::allowEnrollmentWhen(fn (User $user) => $user->approved_at !== null);
```

That replaces Keyring's own rule, so only use it when approving an account means you know it's its owner's. See [Who May Enroll](authenticators.md#who-may-enroll).
