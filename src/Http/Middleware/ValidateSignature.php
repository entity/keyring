<?php

declare(strict_types=1);

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\ValidateSignature as Middleware;
use Illuminate\Support\Facades\URL;
use Keyring\Events\LinkRefused;

/**
 * Laravel's signed link check, which also puts a link it turns away on
 * record. What is refused, and how it's answered, is still Laravel's.
 */
class ValidateSignature extends Middleware
{
    /**
     * @param  Request  $request
     * @param  array<int, string>|null  $args
     */
    public function handle($request, Closure $next, ...$args)
    {
        [$relative, $ignore] = $this->parseArguments($args);

        if (! $request->hasValidSignatureWhileIgnoring($ignore, ! $relative)) {
            LinkRefused::dispatch(
                (string) $request->route()?->getName(),
                URL::hasCorrectSignature($request, ! $relative, $ignore) ? 'expired' : 'signature',
            );
        }

        return parent::handle($request, $next, ...$args);
    }
}
