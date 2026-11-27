<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Contracts\Responses\SignedOutResponse;
use Keyring\Enums\ImpersonationEndReason;
use Keyring\Exceptions\ImpersonationRefused;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Starting and stopping an impersonation. Both clear what the browser
 * cached and stored for the site, as signing out does: none of one
 * account's pages stay for the other to see.
 */
class ImpersonationController
{
    use ChoosesFormat, RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected Impersonation $impersonation,
    ) {}

    /**
     * Sign in as the user with this ID, as Keyring's guard loads them. One
     * that doesn't exist is refused like one that may not be impersonated,
     * so the answer doesn't say which IDs have an account.
     */
    public function store(Request $request, string $user): Response
    {
        $found = $this->keyring->provider()->retrieveById($user);

        $this->impersonation->start($request, $found instanceof Model ? $found : throw new ImpersonationRefused('not_allowed'));

        return $this->clearSiteData($this->status('impersonation-started', redirect: $this->impersonation->redirectTo())->toResponse($request));
    }

    /**
     * Stop impersonating, and go back to being whoever started it. When
     * their own session has ended meanwhile, the browser is signed out.
     */
    public function destroy(Request $request): Response
    {
        abort_unless($this->impersonation->active($request), 404);

        if ($this->impersonation->stop($request) === null) {
            return $this->keyring->response(SignedOutResponse::class, reason: ImpersonationEndReason::ImpersonatorSessionEnded->value)->toResponse($request);
        }

        return $this->clearSiteData($this->status('impersonation-ended', redirect: $this->impersonation->returnTo())->toResponse($request));
    }
}
