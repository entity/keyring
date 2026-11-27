# Recipes

- [Introduction](#introduction)
- [Locations With stevebauman/location](#locations-with-stevebaumanlocation)
- [Locations From Cloudflare](#locations-from-cloudflare)
- [Emails With Maizzle](#emails-with-maizzle)
- [SMS Codes](#sms-codes)
- [Social Login](#social-login)
- [Usernames Instead of Email Addresses](#usernames-instead-of-email-addresses)
- [Links for Apps on Several Domains](#links-for-apps-on-several-domains)
- [Storing Less About Requests](#storing-less-about-requests)
- [Accounts an Admin Approves](#accounts-an-admin-approves)
- [An App Whose Every Page Needs AAL2](#an-app-whose-every-page-needs-aal2)

## Introduction

This page contains worked examples of the hooks described in [Extending Keyring](extending.md), using the packages developers most often reach for. Each example was run against a real application before it was written down.

The examples that use another package were written against `stevebauman/location` 7.8, `laravel/vonage-notification-channel` 3.3, and `@maizzle/framework` 6.3, on Laravel 13. If you're using a newer version, check that package's own documentation.

## Locations With stevebauman/location

Keyring shows where a device signed in from, and the [`NewCountry` and `ImpossibleTravel` signals](risk.md) need a location to work. Keyring asks a locator class for that location, and [`stevebauman/location`](https://github.com/stevebauman/location) can serve as that class.

To install it, run these commands:

```bash
composer require stevebauman/location
php artisan vendor:publish --provider="Stevebauman\Location\LocationServiceProvider"
```

Next, create a locator class that implements the `LocatesIps` contract. It uses the package to look up the request's IP address:

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

Next, point Keyring at your locator, turn on devices, and choose the signals you want:

```php
// config/keyring.php
'features' => [
    // ...
    Features::devices(),
],

'devices' => [
    'locator' => App\Keyring\IpLocator::class,
],
```

```php
// KeyringServiceProvider
Keyring::risk()->signals([NewDevice::class, NewCountry::class, ImpossibleTravel::class]);
```

There are three things you should know about this setup:

- **The default driver calls an API.** Keyring asks the locator at most once per request, and only for requests that need a location. A sign in still waits on that call, though. For production, set `location.driver` to the MaxMind driver with a local database file, which answers from disk.
- **The package returns a fixed test location until you turn that off.** `LOCATION_TESTING` defaults to `true`, which locates every request at a Google address in the United States. Set `LOCATION_TESTING=false` outside local development.
- **A failed lookup doesn't stop the sign in.** If the locator throws, Keyring treats the location as unknown for that request and reports the exception.

If your application runs behind a load balancer, configure Laravel's [trusted proxies](https://laravel.com/docs/requests#configuring-trusted-proxies). Otherwise, every request carries the balancer's address and therefore the same location.

In your tests, the `Location::fake` method gives you a location without performing a lookup:

```php
use Stevebauman\Location\Facades\Location;
use Stevebauman\Location\Position;

Location::fake(['*' => Position::make(['countryCode' => 'NL', 'cityName' => 'Amsterdam'])]);
```

## Locations From Cloudflare

If your application can only be reached through Cloudflare, Cloudflare can tell you where each request came from, without any lookup at all. The `Keyring\Devices\HeaderLocator` class reads those headers for you:

```php
// config/keyring.php
'devices' => [
    'locator' => Keyring\Devices\HeaderLocator::class,
],
```

Cloudflare sends `CF-IPCountry` by default. The city, region, and coordinates, which impossible travel needs, are provided by its "Add visitor location headers" managed transform.

> [!WARNING]
> Only use this approach when requests can't reach your application without going through the proxy. Anyone who can reach your application directly can send these headers themselves and choose their own location.

For another proxy or CDN, bind the locator with your own header names. See [Locations](devices-and-sessions.md#locations).

## Emails With Maizzle

Every email Keyring sends is a [notification class](security-log-and-emails.md#security-emails), Keyring's own unless your app gives one with `Keyring::notifications()`, so you can render it with any template you like. [Maizzle](https://maizzle.com) builds email-safe HTML from Vue and Tailwind, and it can write Blade views.

To install it, run:

```bash
npm install -D @maizzle/framework
```

Next, configure Maizzle to write Blade views:

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

Then import Tailwind in a stylesheet:

```css
/* resources/emails/tailwind.css */
@import "@maizzle/tailwindcss";
```

A template is a Vue file. Anything that changes from one email to the next is a Blade variable inside `<Raw>`, which Maizzle passes through untouched:

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

      <Raw>@isset($contact)</Raw>
      <Text class="text-sm text-slate-500"><Raw>{{ __("If this wasn't you and you need help, contact us:") }} {{ $contact }}</Raw></Text>
      <Raw>@endisset</Raw>
    </Container>
  </Layout>
</template>
```

Running `npx maizzle build` writes `notice.blade.php` and `text/notice.blade.php`. Tell `SecurityNotice` to return those views, and every notice will use the same template:

```php
// app/Providers/KeyringServiceProvider.php
use Illuminate\Notifications\Messages\MailMessage;
use Keyring\Notifications\SecurityNotice;

SecurityNotice::toMailUsing(function (SecurityNotice $notice, object $notifiable) {
    $details = array_filter([__('When') => $notice->when, __('Device') => $notice->device, __('IP address') => $notice->ip]);

    return (new MailMessage)->subject($notice->subject())->view(
        ['html' => 'emails.keyring.notice', 'text' => 'emails.keyring.text.notice'],
        [
            'subject' => $notice->subject(),
            'intro' => $notice->intro(),
            'details' => array_map(fn (string $label, string $value) => ['label' => $label, 'value' => $value], array_keys($details), $details),
            'actionText' => $notice->action(),
            'actionUrl' => $notice->action() === null ? null : $notice->url,
            'contact' => $notice->contact,
        ],
    );
});
```

The `$notice->contact` property holds your [support contact](security-log-and-emails.md#a-support-contact), which is `null` until you set one. A template of your own must display it itself, as the one above does. Keyring's own template does so in the `toMail` method that this callback replaces, and also turns a URL or an address into a link, where this version prints it as plain text.

Each of the [emails a flow needs](security-log-and-emails.md#emails-a-flow-needs), such as the emailed code, has its own shape. To give one of those a template, extend Keyring's class and register yours, as [Your Own Templates](security-log-and-emails.md#your-own-templates) shows.

There are two things that often catch people out:

- **Keep `=>` and `>` out of the Blade inside `<Raw>`.** Maizzle writes them as HTML entities, which breaks the directive. Pass a list of `['label' => ..., 'value' => ...]` rather than looping over keys and values, and write `@if ($details !== [])` rather than counting the items.
- **Blade's `{{ }}` is what keeps the HTML safe.** A key's name is whatever the user typed, and escaping stops it from adding a link to a genuine security email. Don't swap it for `{!! !!}` in the HTML views.

The [example application](https://github.com/keyringphp/example#emails) has the whole setup: five templates, a shared frame, the four emails a flow needs, and a local page that previews each one.

## SMS Codes

A factor that sends a code extends `Keyring\Factors\CodeFactor`, which handles expiry, guess limits, resending, and enrollment. The factor in this example sends its code by SMS, using Laravel's Vonage channel.

To install the channel, run:

```bash
composer require laravel/vonage-notification-channel
```

Next, create the factor. It asks for the user's phone number when they add the factor, and sends each code to that number:

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

The factor sends its messages with a notification class of its own:

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

Register the factor alongside your others:

```php
Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, SmsCode::class]);
```

Users can then add it like any other sign-in method. Your form posts `phone` to `POST /user/authenticators/sms`, and then posts the code to `POST /user/authenticators/sms/confirm`. While the account has no [established](authenticators.md#established-authenticators) second factor, the first request also needs the user's `password` (see [The Password for a First Second Factor](authenticators.md#the-password-for-a-first-second-factor)).

Don't queue the notification, so the code arrives while the user is still waiting. Confirming the enrollment proves that the number can receive codes, and a code only verifies the phone it was sent to.

> [!WARNING]
> SMS is a weak second factor. Numbers can be moved to a new SIM by someone who talks the carrier into it.

Unlike email, NIST SP 800-63B-4 still accepts SMS as an authenticator, so this factor keeps `CodeFactor`'s possession category, and a password with a texted code counts as an AAL2 session. It's the one authenticator NIST calls restricted (Sec. 3.1.3.3 and 3.2.9), which places conditions on your application that Keyring can't meet for you:

- Every user has to be offered another second factor that isn't restricted.
- Every user has to be told about the risks of text messages.
- You have to plan for the day when text messages are no longer accepted.

Codes may last ten minutes at most. For these reasons, register SMS alongside an authenticator app or passkeys, never in their place, and say so on the page where users choose a factor. By default, each account can be sent [three codes every ten minutes](configuration.md#pending-logins-timebox-and-rate-limits), which also caps how much a stranger can make you spend.

To use a different provider, only the `deliver` method needs to change. Call that provider's SDK there, or route the notification to its channel.

## Social Login

Keyring signs users in with Google, Microsoft, GitHub, and any OpenID Connect provider itself, with the `SingleSignOn` factor. See [Single Sign-On](sso.md), and [More Identity Providers](sso-providers.md) for providers beyond those three, such as GitLab, Okta, Discord, or Facebook. If you followed the Socialite recipe that used to be here, [Migrating From the Socialite Recipe](sso.md#migrating-from-the-socialite-recipe) moves your `github_id` links over.

## Usernames Instead of Email Addresses

If users sign in with a handle and also have an email address, tell Keyring which attribute is which:

```php
// config/keyring.php
'username' => 'handle',

'email' => 'email',
```

The login form then posts `handle` and `password`. Password resets, email changes, and email codes continue to use the email address.

Keyring lowercases what the user types before it looks them up. Store handles in lowercase, or keep their case by returning the trimmed value from `Keyring::normalizeUsernamesUsing`, like this: `Keyring::normalizeUsernamesUsing(fn (string $username) => trim($username))`.

If you want to accept either one in the same field, leave `username` set to `email` and find the user yourself:

```php
use App\Models\User;
use Illuminate\Http\Request;

Keyring::findUsersUsing(fn (Request $request) => User::query()
    ->where('email', $request->string('email')->lower()->value())
    ->orWhere('handle', $request->string('email')->lower()->value())
    ->first());
```

Guesses at either one count against the same account, and the sign-in form doesn't reveal that the two belong together. See [Rate Limiting](security.md#rate-limiting) and [Finding the User](sign-in-flow.md#finding-the-user).

## Links for Apps on Several Domains

Keyring builds every emailed link from `APP_URL`. When each tenant has its own domain, start the links from that domain instead:

```php
Keyring::linkRootUsing(fn () => tenant()?->url ?? config('app.url'));
```

The callback runs whenever a link is built. That happens while handling a request, or in the queued job that sends the email. Read the tenant from wherever your tenancy package stores it in both places.

Return a value that your server already knows. The request's `Host` header is whatever the sender wrote, and a reset link built from it would deliver a real token to their site.

If a tenant scope on your user model hides every user on the central domain, this matters even more. A confirmation link opened there finds no account and reports that it's invalid, so each tenant's links have to open on that tenant's own domain.

Passkeys are tied to a domain as well. If each tenant registers its own passkeys, set `webauthn.relying_party.id` and `webauthn.origins` for each tenant. See [Passkeys & Security Keys](passkeys.md#relying-party-and-origins).

## Storing Less About Requests

Keyring stores the request's IP address on devices, sessions, and security log entries, and it passes that address to security notices. To store only the network instead, anonymize the address:

```php
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;

// 203.0.113.7 becomes 203.0.113.0
Keyring::recordIpsUsing(fn (Request $request) => IpUtils::anonymize((string) $request->ip()));
```

Alternatively, return `null` to store no address at all. Rate limits and the locator still see the real address, since neither one stores it.

You can also configure how long Keyring keeps records:

```php
// config/keyring.php
'security_log' => ['keep_for' => '30d'],

'devices' => ['keep_revoked_for' => '7d', 'keep_unseen_for' => '90d'],

'email_changes' => ['keep_ended_for' => '7d'],
```

The `keyring:prune` Artisan command deletes records older than those periods, and Keyring [schedules it to run daily](devices-and-sessions.md#pruning) for you. Force deleting a user also deletes their devices, sign-in methods, pending changes, sign-in changes, and log entries at the same time.

You can also keep less by leaving features off. To keep no devices at all, leave `Features::devices()` off. The `keyring_events` table is always created, but without `Features::securityLog()` nothing is written to it, and the events are written to [your application's log](security-log-and-emails.md#without-the-table) instead. How long those entries are kept is then up to that log channel. [What Keyring Keeps](security.md#what-keyring-keeps) lists everything Keyring stores.

## Accounts an Admin Approves

If someone reviews each sign-up in your application, you may prevent anyone from signing in until they've been approved:

```php
use App\Models\User;

// Only approved accounts can sign in, however they try: the password, a
// passkey, "remember me". Everyone else gets the same answer as a wrong
// password. Registering never signs them in.
Keyring::allowSignInWhen(fn (User $user) => $user->approved_at !== null);
```

Withdrawing an approval signs the account out on its next request, and that request also ends the account's other sessions. To end every session as soon as you withdraw the approval, without waiting for a request, sign the account out yourself:

```php
use Keyring\Sessions\Sessions;

$user->forceFill(['approved_at' => null])->save();

app(Sessions::class)->signOutEverywhere($user);
```

See [Who May Sign In](sign-in-flow.md#who-may-sign-in).

Approval can also decide whether a user may add a sign-in method, in place of verifying their email address:

```php
Keyring::allowEnrollmentWhen(fn (User $user) => $user->approved_at !== null);
```

This replaces Keyring's own rule, so only use it when approving an account means you know it belongs to its owner. See [Who May Enroll](authenticators.md#who-may-enroll).

## An App Whose Every Page Needs AAL2

Some applications can't show anything to a session that hasn't proved two factors. For example, NIST SP 800-63B-4 (Sec. 2) asks federal agencies to choose at least AAL2 wherever personal information is made available online. By default, Keyring signs users in with whatever they have and lets an assurance level lapse without ending the session. To make AAL2 the minimum, you need to make three changes.

First, update the policy and the factors. Don't register email codes, which [aren't a factor](factors.md#what-turning-email-codes-on-means):

```php
// app/Providers/KeyringServiceProvider.php
Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, WebAuthn::passkeys()]);

Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());
```

The `ifEnrolled` condition stays in place, so a new user can sign in once with their password to set up a second factor. Next, add the `keyring.enrolled` middleware, which keeps that user from reaching anything else until they've done so, and put your pages in a `keyring:aal2` group, which asks every other session for AAL2. Tell Keyring where the enrollment page is with `enrollment_url`:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: ['keyring.enrolled']);
})
```

```php
// routes/web.php
Route::middleware(['auth', 'keyring:aal2'])->group(function () {
    // Every page of the app, except the one users add a second factor on.
});

Route::get('/settings/security', [SecurityController::class, 'edit'])->middleware('auth');
```

```php
// config/keyring.php
'enrollment_url' => '/settings/security',
```

Last, end the session when AAL2 runs out. Otherwise, the session would carry on as AAL1:

```php
// config/keyring.php
'sessions' => [
    'end_on_lapse' => true,
],
```

With these settings in place:

- A session that signed in with two factors ends after an hour without a request, or 24 hours after those factors were proved, and the user signs in again with both. To change those numbers, edit `sessions.levels.aal2`.
- A new user's first session is signed in with one factor, so it isn't ended. That session can reach the enrollment page and Keyring's own routes, but nothing in the group above. The enrollment page asks for the password along with the new factor, since the account has no [established](authenticators.md#the-password-for-a-first-second-factor) second factor yet. Adding the second factor proves it, which takes the session to AAL2 for as long as that level lasts. After that, `keyring:aal2` asks for both factors again.
- "Remember me" doesn't bring a session back, so leave it off your login form.
- Laravel's own `session.lifetime` still ends an idle session sooner if it's shorter than an hour. Set it to 60 or more.

What Keyring can't do for you is the rest of what NIST asks at AAL2. Phishing-resistant sign in has to be on offer, which means registering passkeys as shown above. A federal agency's server cryptography also has to be validated.
