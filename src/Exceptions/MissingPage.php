<?php

namespace Keyring\Exceptions;

use LogicException;

class MissingPage extends LogicException
{
    /**
     * @param  list<string>  $props
     */
    public static function for(string $page, string $view, array $props): self
    {
        return new self(sprintf(
            'Keyring\'s [%s] page has no Blade view. Create resources/views/%s.blade.php (it receives %s), or render something else with Keyring::page(\'%1$s\', ...). See "Pages" in the sign-in flow docs.',
            $page,
            str_replace('.', '/', $view),
            $props === [] ? 'no data' : implode(', ', array_map(fn (string $prop) => '$'.$prop, $props)),
        ));
    }
}
