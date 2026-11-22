<?php

declare(strict_types=1);

namespace Keyring\Concerns;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Lang;
use Inertia\ComponentNotFoundException;
use Inertia\ResponseFactory;
use Keyring\Exceptions\MissingPage;
use Keyring\Http\Responses\StatusResponse;
use Keyring\Support\EncryptedSession;

/**
 * Keyring's pages, rendered by the app: Inertia components or Blade views,
 * or the page's name and props as JSON for a frontend Laravel doesn't serve.
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
     * Render one of Keyring's pages: a closure the app gave for it, then the
     * page's name and props for a JSON request, then Inertia when installed
     * and Blade otherwise. With keyring.pages off, for an app whose pages
     * are all in a frontend of its own, those last two are a 404.
     *
     * @param  array<string, mixed>  $props
     */
    public function render(string $name, array $props = []): mixed
    {
        // As ChoosesFormat decides for every other response. A frontend
        // Laravel doesn't serve keeps its own place, so a JSON request isn't
        // noted as the page to go back to, as Laravel doesn't note an XHR.
        $request = request();
        $json = $request->expectsJson() && ! $request->hasHeader('X-Inertia');
        $component = $this->pages[$name] ?? 'auth/'.$name;

        // The app's own answer for the page, for JSON clients too: it may be
        // how the app keeps a prop from being shown.
        if ($component instanceof Closure) {
            if (! $json) {
                $this->rememberPage();
            }

            return $component($props);
        }

        if ($json) {
            return new JsonResponse(['page' => $name, 'props' => (object) $props]);
        }

        // Nothing renders, so there's no page to come back to either.
        abort_if(config('keyring.pages') === false, 404);

        $this->rememberPage();

        if (class_exists(ResponseFactory::class)) {
            try {
                return resolve(ResponseFactory::class)->render($component, $props);
            } catch (ComponentNotFoundException) {
                throw MissingPage::forInertia($name, $component, array_keys($props));
            }
        }

        // The tests always have Inertia installed, so they never get here.
        // @codeCoverageIgnoreStart
        $view = str_replace('/', '.', $component);

        throw_unless(view()->exists($view), MissingPage::forBlade($name, $view, array_keys($props)));

        return view($view, $props);
        // @codeCoverageIgnoreEnd
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
