<?php

declare(strict_types=1);

namespace Keyring\Login;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Support\Uri;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Sessions\RegisteredSession;
use Throwable;

/**
 * Where a user was going when Keyring sent them off to enroll or to choose
 * a new password, to carry on there once they have.
 *
 * Kept as {url, user, at} under Keyring's own keys, never url.intended: the
 * login just used that up, and the app and other packages write to it too.
 * It's saved only for a page the browser navigated to, so an image, a
 * fetch() or a prefetch can't take its place, and it's only handed back on
 * this app's own origin, to the user it was saved for, within the hour.
 *
 * A page saved with the requirement that sent the user away keeps it as
 * "requirement", and is only handed back once the account can meet it.
 */
class Detours
{
    use ChoosesFormat;

    /** Where a user was going when sent to enroll. */
    public const string ENROLLMENT = 'keyring.continue_after_enrollment';

    /** Where a user was going when held to choose a new password. */
    public const string PASSWORD_CHANGE = 'keyring.continue_after_password_change';

    /** Seconds a saved page stays worth going back to. */
    public const int LIFETIME = 3600;

    /**
     * Keyring's own pages, and the ones it sends users to: none is a place
     * to come back to. Pages opened from emailed links are left out too:
     * their URL holds the link's token, and some of them, like confirming
     * an email change, stop working once the password changes.
     *
     * @var list<string>
     */
    protected array $own = ['keyring.*', 'login', 'register', 'password.*', 'verification.*', 'logout', 'user-password.update'];

    /**
     * What the page being saved needs the account to meet, while remember()
     * hands it to put(), which saves it with the page.
     */
    protected ?Requirement $requiring = null;

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Save where this request was going: the page itself, or for one of
     * Keyring's own pages only the $url it says it was there for. Anything
     * but a navigation, and anything off this origin or on the detour's own
     * page, leaves what's saved alone.
     *
     * With a $requirement, the page is only handed back once the account
     * can meet it: what sent the user away, so meeting less would only send
     * them back.
     */
    public function remember(Request $request, string $key, ?string $url = null, ?Requirement $requirement = null): void
    {
        if (! $this->isNavigation($request)) {
            return;
        }

        $url ??= $request->routeIs(...$this->own) ? null : $request->fullUrl();

        if ($url === null || ! $this->isOwnOrigin($request, $url) || $this->isDestination($key, $url)) {
            return;
        }

        $this->requiring = $requirement;

        try {
            $this->put($request, $key, $url);
        } finally {
            $this->requiring = null;
        }
    }

    /**
     * The saved page, if it's still one to go to for the signed-in user.
     * One whose requirement the account can't meet yet stays saved, for
     * the sign-in method that does. Anything else is forgotten either way.
     * A page saved without a requirement, as before there was one, is
     * handed back as it always was.
     */
    public function pull(Request $request, string $key): ?string
    {
        if (! $request->hasSession()) {
            return null;
        }

        $saved = $request->session()->pull($key);
        $user = $this->keyring->guard()->user();
        // Only an Eloquent user has authenticators to meet a requirement with.
        $model = $user instanceof Model ? $user : null;

        if (! is_array($saved) || ! $user instanceof Authenticatable) {
            return null;
        }

        $url = $saved['url'] ?? null;
        $at = $saved['at'] ?? null;
        $age = is_int($at) ? now()->getTimestamp() - $at : -1;

        if (! is_string($url)
            || ($saved['user'] ?? null) !== $this->owner($user)
            || $age < 0 || $age > static::LIFETIME
            || ! $this->isOwnOrigin($request, $url)) {
            return null;
        }

        if (! array_key_exists('requirement', $saved)) {
            return $url;
        }

        $requirement = $this->requirementIn($saved['requirement']);

        if ($requirement === null || $model === null) {
            return null;
        }

        if ($this->keyring->for($model)->withoutFallbacks()->canMeet($requirement)) {
            return $url;
        }

        $request->session()->put($key, $saved);

        return null;
    }

    /**
     * Forget both, as a new sign in does: the session keeps its other data,
     * and what one account saved has no business reaching another.
     */
    public function forget(Request $request): void
    {
        $request->session()->forget([static::ENROLLMENT, static::PASSWORD_CHANGE]);
    }

    /**
     * Save $url under $key for the signed-in user, replacing what was saved
     * before. This is the override point: remember() only gets here after
     * its checks, so an app that binds its own subclass can skip pages it
     * never wants carried on to, and call the parent for the rest. $url is
     * the page being saved. On the confirm page $request is the confirm
     * page itself, so check $url, not $request. What the page needs the
     * account to meet, if remember() was given it, is $this->requiring, and
     * is saved with it.
     */
    protected function put(Request $request, string $key, string $url): void
    {
        $user = $this->keyring->guard()->user();

        if ($user instanceof Authenticatable) {
            $request->session()->put($key, [
                'url' => $url,
                'user' => $this->owner($user),
                'at' => now()->getTimestamp(),
                ...$this->requiring === null ? [] : ['requirement' => $this->requiring->toArray()],
            ]);
        }
    }

    /**
     * The requirement a page was saved with, or null when what's there
     * isn't one, and the page is refused.
     */
    protected function requirementIn(mixed $saved): ?Requirement
    {
        try {
            // @phpstan-ignore argument.type (fromArray() throws for anything it can't read)
            return is_array($saved) ? Requirement::fromArray($saved) : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Whether the browser is going to this page: a GET it says is a
     * top-level navigation, or an Inertia visit that isn't a prefetch or a
     * partial reload. Without either header nothing tells it from an image
     * or a background request, so it doesn't count.
     */
    protected function isNavigation(Request $request): bool
    {
        if (! $request->isMethod('GET') || ! $request->hasSession() || $this->wantsJson($request) || $this->isPrefetch($request)) {
            return false;
        }

        if ($request->hasHeader('X-Inertia')) {
            return $request->header('Purpose') !== 'prefetch'
                && ! $request->hasHeader('X-Inertia-Partial-Component')
                && ! $request->hasHeader('X-Inertia-Partial-Data');
        }

        return $request->header('Sec-Fetch-Mode') === 'navigate'
            && in_array($request->header('Sec-Fetch-Dest'), [null, 'document'], true);
    }

    /**
     * Whether the browser is only fetching the page ahead of time, or
     * rendering it out of sight. Laravel's prefetch() compares the whole
     * header, so it misses Chrome's "prefetch;prerender".
     */
    protected function isPrefetch(Request $request): bool
    {
        return $request->prefetch() || str_starts_with(strtolower((string) $request->header('Sec-Purpose')), 'prefetch');
    }

    /**
     * Whether a URL is the page this detour sends users to, matched by path
     * as the middleware let it through. Coming back to it would only leave
     * them where they already are.
     */
    protected function isDestination(string $key, string $url): bool
    {
        $destination = config($key === static::ENROLLMENT ? 'keyring.enrollment_url' : 'keyring.password_change_url');

        return is_string($destination) && Str::is(Uri::of($destination)->path(), rawurldecode(Uri::of($url)->path()));
    }

    /**
     * Whether a URL is on the origin of this request, as ChoosesFormat
     * checks where to come back to.
     */
    protected function isOwnOrigin(Request $request, string $url): bool
    {
        $root = $request->getSchemeAndHttpHost();

        return $url === $root || str_starts_with($url, $root.'/') || str_starts_with($url, $root.'?');
    }

    /**
     * Who it was saved for, as the session registry tells users apart: the
     * model's connection and table, and the ID.
     *
     * @return array{type: string, id: string}
     */
    protected function owner(Authenticatable $user): array
    {
        return ['type' => RegisteredSession::typeOf($user), 'id' => (string) $user->getAuthIdentifier()];
    }
}
