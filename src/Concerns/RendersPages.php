<?php

declare(strict_types=1);

namespace Keyring\Concerns;

use Closure;
use Illuminate\Support\Facades\Lang;
use Inertia\ComponentNotFoundException;
use Inertia\ResponseFactory;
use Keyring\Exceptions\MissingPage;
use Keyring\Http\Responses\StatusResponse;
use Keyring\Support\EncryptedSession;

/**
 * Keyring's pages, rendered by the app: Inertia components or Blade views.
 */
trait RendersPages
{
    /** @var array<string, string|Closure(array<string, mixed>): mixed> */
    protected array $pages = [];

    /**
     * Use a different Inertia component (or a closure) for one of Keyring's pages.
     *
     * @param  string|Closure(array<string, mixed>): mixed  $component
     */
    public function page(string $name, string|Closure $component): static
    {
        $this->pages[$name] = $component;

        return $this;
    }

    /**
     * Render one of Keyring's pages: Inertia when installed, Blade otherwise.
     *
     * @param  array<string, mixed>  $props
     */
    public function render(string $name, array $props = []): mixed
    {
        $this->rememberPage();

        $component = $this->pages[$name] ?? 'auth/'.$name;

        if ($component instanceof Closure) {
            return $component($props);
        }

        if (class_exists(ResponseFactory::class)) {
            try {
                return resolve(ResponseFactory::class)->render($component, $props);
            } catch (ComponentNotFoundException) {
                throw MissingPage::forInertia($name, $component, array_keys($props));
            }
        }

        $view = str_replace('/', '.', $component);

        throw_unless(view()->exists($view), MissingPage::forBlade($name, $view, array_keys($props)));

        return view($view, $props);
    }

    /**
     * Note the page being rendered as the one a failed form goes back to.
     * The pages emailed links open send no Referer (their URLs carry a
     * token), and Laravel doesn't note an Inertia visit as the last page
     * seen, so "back" would otherwise be whichever page was last loaded in
     * full.
     */
    protected function rememberPage(): void
    {
        $request = request();

        if ($request->isMethod('GET') && $request->hasSession() && ! $request->prefetch()) {
            $request->session()->setPreviousUrl($request->fullUrl());
        }
    }

    /**
     * The message for a status slug Keyring flashes or returns, such as
     * "device-revoked", from keyring::status. Null for anything else.
     */
    public function statusMessage(mixed $status): ?string
    {
        $message = is_string($status) && Lang::has($key = 'keyring::status.'.$status) ? __($key) : null;

        return is_string($message) ? $message : null;
    }

    /**
     * What the last status response flashed for the page beside its status,
     * such as new recovery codes, or one key of it in dot notation, like
     * "enrollment.secret". It's kept encrypted in the session, so read it
     * here rather than from session('keyring.result'). Null, or $default,
     * when nothing was flashed.
     */
    public function result(?string $key = null, mixed $default = null): mixed
    {
        $request = request();
        $result = $request->hasSession() ? app(EncryptedSession::class)->get(StatusResponse::RESULT) : null;

        return $key === null ? ($result ?? $default) : data_get($result, $key, $default);
    }
}
