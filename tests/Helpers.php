<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Mail\Markdown;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Keyring\Enums\SsoFailure;
use Keyring\Exceptions\SsoFailed;
use Keyring\Factors\Totp;
use Keyring\KeyringManager;
use Keyring\Models\SecurityEvent;
use Keyring\Sso\Identity;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\Staff;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\TestCase;
use Keyring\WebAuthn\Ceremonies;
use Keyring\WebAuthn\Profile;
use Monolog\Handler\TestHandler;
use Monolog\LogRecord;
use ParagonIE\ConstantTime\Base64UrlSafe;
use PragmaRX\Google2FA\Google2FA;

// The published actions in stubs/app are what the tests run, against the
// fixture user standing in for the app's.
class_alias(User::class, App\Models\User::class);

const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';

const CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36';

/**
 * A verified user whose password is "password".
 *
 * @param  array<string, mixed>  $attributes
 */
function taylor(array $attributes = []): User
{
    return User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now(), ...$attributes]);
}

/**
 * An account of a second model, whose ID overlaps with the users'. The
 * password is "password".
 */
function staff(): Staff
{
    return Staff::create(['id' => User::query()->max('id') ?? 1, 'name' => 'Staff', 'email' => 'staff@example.com', 'password' => 'password']);
}

/**
 * Whether the database treats addresses that differ by an accent as one, as
 * MySQL's default collation does: two such accounts can't both exist there,
 * and either spelling finds the one that does.
 */
function databaseIgnoresAccents(): bool
{
    return in_array(DB::connection()->getDriverName(), ['mysql', 'mariadb'], true);
}

/**
 * A passkey as laravel/passkeys keeps one: its credential ID and the record
 * a real registration produced, with a new key or the one given.
 *
 * @return array{credential_id: string, credential: string}
 */
function passkeyRow(User $user, ?VirtualAuthenticator $key = null): array
{
    $ceremonies = app(Ceremonies::class);
    $options = $ceremonies->creationOptions($user, Profile::passkeys(), []);
    $record = $ceremonies->register(json_encode(($key ?? new VirtualAuthenticator)->register($ceremonies->toBrowser($options))), $ceremonies->toJson($options), Profile::passkeys());

    return [
        'credential_id' => Base64UrlSafe::encodeUnpadded($record->publicKeyCredentialId),
        'credential' => $ceremonies->toJson($record),
    ];
}

/**
 * What an authenticator app shows for the secret, now or some 30 second
 * steps from now.
 */
function totpCode(string $secret, int $step = 0): string
{
    return app(Google2FA::class)->oathTotp($secret, Totp::timestep($step));
}

/**
 * Turn on Keyring's own notification for each type, or for every one: the
 * suspected clone, which starts off, and any a test turned off.
 *
 * @param  list<string>|null  $types
 */
function sendNotifications(?array $types = null): void
{
    $types ??= KeyringManager::NOTIFICATIONS;

    Keyring\Facades\Keyring::notifications(array_combine($types, array_map(
        fn (string $type) => 'Keyring\\Notifications\\'.Str::studly($type),
        $types,
    )));
}

/**
 * Send back an earlier copy of the session (from session()->all()), as a
 * browser can when the session is kept in its cookie: Laravel's "cookie"
 * session driver has nothing on the server to say the copy is out of date.
 *
 * @param  array<string, mixed>  $earlier
 */
function sendBackSession(array $earlier): void
{
    test()->flushSession();
    app('auth')->forgetGuards();
    test()->withSession($earlier);
}

/**
 * Turn on only these features and register Keyring's routes again, since
 * they're read once at boot.
 *
 * @param  list<string>  $features
 */
function withFeatures(array $features): void
{
    config(['keyring.features' => $features]);

    reloadRoutes();
}

/**
 * Register Keyring's routes again, for config that's read once at boot:
 * the features, and whether any identity provider is configured.
 */
function reloadRoutes(): void
{
    app('router')->setRoutes(new RouteCollection);
    Keyring\Facades\Keyring::routes();
    app('router')->getRoutes()->refreshNameLookups();
}

/**
 * Registration as it was before it hid who has an account: the form says
 * when an address is taken, new users are signed in straight away, and an
 * account can be signed in before its address is verified.
 */
function revealTakenAddresses(): void
{
    config(['keyring.registration.reveal_taken' => true]);
}

/**
 * A mail message's HTML and plain-text parts, as the mail channel renders them.
 *
 * @return array{html: string, text: string}
 */
function renderedMail(MailMessage $mail): array
{
    return [
        'html' => (string) $mail->render(),
        'text' => (string) app(Markdown::class)->renderText($mail->markdown, $mail->data()),
    ];
}

/**
 * Press the button on the page a signed link opens: it posts the link's
 * signature in the body, to the link's path.
 */
function postSignedLink(string $url): TestResponse
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $fields);

    return test()->post((string) parse_url($url, PHP_URL_PATH), $fields);
}

function expectValidPhp(string $path): void
{
    exec(escapeshellarg(PHP_BINARY).' -l '.escapeshellarg($path).' 2>&1', $output, $status);

    expect($status)->toBe(0, implode("\n", $output));
}

/**
 * The types logged so far, oldest first.
 *
 * @return list<string>
 */
function loggedTypes(): array
{
    return SecurityEvent::query()->oldest('id')->pluck('type')->all();
}

function logEntry(string $type): SecurityEvent
{
    return SecurityEvent::query()->where('type', $type)->sole();
}

/**
 * Send the app's log to a channel that keeps its lines in memory.
 */
function logTo(string $channel = 'memory'): TestHandler
{
    config(["logging.channels.{$channel}" => ['driver' => 'monolog', 'handler' => TestHandler::class]]);

    return Log::channel($channel)->getLogger()->getHandlers()[0];
}

/**
 * What Keyring wrote to a log channel, as [level, type, context].
 *
 * @return list<array{string, string, array<string, mixed>}>
 */
function written(TestHandler $handler): array
{
    return collect($handler->getRecords())
        ->filter(fn (LogRecord $record) => str_starts_with($record->message, 'Keyring: '))
        ->map(fn (LogRecord $record) => [strtolower($record->level->name), substr($record->message, 9), $record->context])
        ->values()
        ->all();
}

/**
 * A request from a browser that holds these cookies and no others. The test
 * client would otherwise send every cookie an earlier request was given, and
 * every response would carry the ones queued for the responses before it.
 *
 * @param  array<string, string>  $cookies
 */
function browser(array $cookies = [], string $agent = FIREFOX): TestCase
{
    Cookie::flushQueuedCookies();
    Auth::forgetGuards();

    return test()->withHeader('User-Agent', $agent)
        ->withCredentials()
        ->withCookies([config('session.cookie') => '', Auth::guard()->getRecallerName() => '', 'remembered_session' => '', 'known_device' => '', ...$cookies]);
}

/**
 * The long-lived cookies a response left the browser with.
 *
 * @return array<string, string>
 */
function keptCookies(TestResponse $response): array
{
    return collect([Auth::guard()->getRecallerName(), 'remembered_session', 'known_device'])
        ->mapWithKeys(fn (string $name) => [$name => $response->getCookie($name)?->getValue()])
        ->filter()
        ->all();
}

const SSO_CALLBACK = 'https://app.test/sso/callback';

/**
 * Send the user to an identity provider: the authorization URL.
 *
 * @param  array<string, mixed>  $data
 */
function ssoStart(string $provider = 'fake', string $purpose = 'login', array $data = []): string
{
    return Keyring\Facades\Keyring::sso()->start($provider, $purpose, SSO_CALLBACK, $data);
}

/**
 * Take the user back from an identity provider's callback URL.
 */
function ssoComplete(string $callback, string $provider = 'fake'): Identity
{
    return Keyring\Facades\Keyring::sso()->complete(Request::create($callback), $provider);
}

/**
 * Why signing in failed, and what it said, or null when it didn't.
 *
 * @return array{SsoFailure, string}|null
 */
function ssoFailure(Closure $callback): ?array
{
    try {
        $callback();
    } catch (SsoFailed $e) {
        return [$e->reason, $e->getMessage()];
    }

    return null;
}

/**
 * The authorization URL's query string.
 *
 * @return array<string, mixed>
 */
function authorizationQuery(string $url): array
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    return $query;
}
