<?php

namespace Keyring\Concerns;

use Closure;
use Illuminate\Support\Facades\Lang;
use Inertia\ComponentNotFoundException;
use Inertia\ResponseFactory;
use Keyring\Exceptions\MissingPage;

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
     * The message for a status slug Keyring flashes or returns, such as
     * "device-revoked", from keyring::status. Null for anything else.
     */
    public function statusMessage(mixed $status): ?string
    {
        return is_string($status) && Lang::has($key = 'keyring::status.'.$status) ? __($key) : null;
    }
}
