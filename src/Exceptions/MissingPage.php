<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use LogicException;

class MissingPage extends LogicException
{
    /**
     * @param  list<string>  $props
     */
    public static function forBlade(string $page, string $view, array $props): self
    {
        return new self(sprintf(
            'Keyring\'s [%s] page has no Blade view. Create resources/views/%s.blade.php (it receives %s), or render something else with Keyring::page(\'%1$s\', ...). See "Pages" in the sign-in flow docs.',
            $page,
            str_replace('.', '/', $view),
            self::list($props, '$'),
        ));
    }

    /**
     * @param  list<string>  $props
     */
    public static function forInertia(string $page, string $component, array $props): self
    {
        return new self(sprintf(
            'Keyring\'s [%s] page has no Inertia component. Create [%s] in your pages directory (it receives %s), or render something else with Keyring::page(\'%1$s\', ...). See "Pages" in the sign-in flow docs.',
            $page,
            $component,
            self::list($props),
        ));
    }

    /**
     * @param  list<string>  $props
     */
    protected static function list(array $props, string $prefix = ''): string
    {
        return $props === [] ? 'no data' : implode(', ', array_map(fn (string $prop) => $prefix.$prop, $props));
    }
}
