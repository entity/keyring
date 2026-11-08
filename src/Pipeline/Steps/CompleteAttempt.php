<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Purpose;
use Keyring\Events\Authenticated;
use Keyring\Events\Confirmed;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Session\SessionAssurance;
use Keyring\Sessions\Sessions;

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
        protected DeviceManager $devices,
        protected Sessions $sessions,
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
            $user = $attempt->user();

            $this->keyring->guard()->login($user, $attempt->remember);
            $context->request->session()->regenerate();
            $this->assurance->reset($attempt->verifications);

            [$device, $new] = $this->devices->signIn($context->request, $user, $attempt->trustDevice);
            $this->sessions->start($context->request, $user, $device, $this->assurance->level());

            Authenticated::dispatch($user, $attempt);

            if ($new) {
                NewDeviceSignedIn::dispatch($user, $device);
            }
        } else {
            $context->request->session()->regenerate();
            $this->assurance->record($attempt->verifications);
            $this->sessions->elevate($context->request, $this->assurance->level());

            // Keep Laravel's own password.confirm middleware happy too.
            $context->request->session()->put('auth.password_confirmed_at', now()->getTimestamp());

            Confirmed::dispatch($attempt->user(), $attempt);
        }

        $context->outcome = Outcome::Complete;

        return $next($context);
    }
}
