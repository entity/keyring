<?php

declare(strict_types=1);

namespace Keyring\Login;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Sessions\RegisteredSession;

/**
 * Where a user was going when Keyring sent them off to enroll or to choose
 * a new password, to carry on there once they have.
 *
 * Kept as {url, user, at} under Keyring's own keys, never url.intended: the
 * login just used that up, and the app and other packages write to it too.
 * It's saved only for a page the browser navigated to, so an image, a
 * fetch() or a prefetch can't take its place, and it's only handed back on
 * this app's own origin, to the user it was saved for, within the hour.
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
     * to come back to.
     *
     * @var list<string>
     */
    protected array $own = ['keyring.*', 'login', 'register', 'password.*', 'verification.*', 'logout', 'user-password.update'];

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Save where this request was going: the page itself, or for one of
     * Keyring's own pages only the $url it says it was there for. Anything
     * but a navigation leaves what's saved alone.
     */
    public function remember(Request $request, string $key, ?string $url = null): void
    {
        $user = $this->keyring->guard()->user();

        if (! $user instanceof Authenticatable || ! $this->isNavigation($request)) {
            return;
        }

        $url ??= $request->routeIs(...$this->own) ? null : $request->fullUrl();

        if ($url !== null && $this->isOwnOrigin($request, $url)) {
            $request->session()->put($key, ['url' => $url, 'user' => $this->owner($user), 'at' => now()->getTimestamp()]);
        }
    }

    /**
     * The saved page, if it's still one to go to for the signed-in user.
     * It's forgotten either way.
     */
    public function pull(Request $request, string $key): ?string
    {
        if (! $request->hasSession()) {
            return null;
        }

        $saved = $request->session()->pull($key);
        $user = $this->keyring->guard()->user();

        if (! is_array($saved) || ! $user instanceof Authenticatable) {
            return null;
        }

        $url = $saved['url'] ?? null;
        $at = $saved['at'] ?? null;
        $age = is_int($at) ? now()->getTimestamp() - $at : -1;

        return is_string($url)
            && ($saved['user'] ?? null) === $this->owner($user)
            && $age >= 0 && $age <= static::LIFETIME
            && $this->isOwnOrigin($request, $url)
                ? $url
                : null;
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
     * Whether the browser is going to this page: a GET it says is a
     * top-level navigation, or an Inertia visit that isn't a prefetch or a
     * partial reload. Without either header nothing tells it from an image
     * or a background request, so it doesn't count.
     */
    protected function isNavigation(Request $request): bool
    {
        if (! $request->isMethod('GET') || ! $request->hasSession() || $this->wantsJson($request)) {
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
