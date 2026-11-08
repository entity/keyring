<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Keyring\Enums\Purpose;
use Keyring\Events\Authenticated;
use Keyring\Events\Confirmed;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Session\SessionAssurance;

/**
 * Signs the user in once the requirement is met, or saves the attempt and
 * asks for another factor.
 */
class CompleteAttempt
{
    public function __construct(
        protected KeyringManager $keyring,
        protected AttemptStore $attempts,
        protected SessionAssurance $assurance,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $attempt = $context->attempt;

        if (! $attempt->complete) {
            $this->attempts->save($attempt);
            $context->outcome = Outcome::Challenge;

            return $next($context);
        }

        $this->attempts->forget($attempt->purpose);

        if ($attempt->purpose === Purpose::Login) {
            $this->keyring->guard()->login($attempt->user(), $attempt->remember);
            $context->request->session()->regenerate();
            $this->assurance->reset($attempt->verifications);

            Authenticated::dispatch($attempt->user(), $attempt);
        } else {
            $context->request->session()->regenerate();
            $this->assurance->record($attempt->verifications);

            // Keep Laravel's own password.confirm middleware happy too.
            $context->request->session()->put('auth.password_confirmed_at', now()->getTimestamp());

            Confirmed::dispatch($attempt->user(), $attempt);
        }

        $context->outcome = Outcome::Complete;

        return $next($context);
    }
}
