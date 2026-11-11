<?php

declare(strict_types=1);

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Support\Facades\Log;
use Keyring\Enums\Purpose;
use Keyring\Events\VerificationRefused;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Login\SignIn;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;

/**
 * Signs the user in (or confirms them) once the requirement is met, or saves
 * the attempt and asks for another factor.
 */
class CompleteAttempt
{
    public function __construct(
        protected AttemptStore $attempts,
        protected SignIn $signIn,
        protected KeyringManager $keyring,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        // Refused by a rate limit, whatever a step in between made of it.
        if ($context->refused) {
            return $context->fail();
        }

        $attempt = $context->attempt();

        if (! $attempt->complete) {
            // A factor was just proved, so whoever planted or copied the old
            // session ID mustn't share the progress.
            $context->request->session()->regenerate(true);

            $this->attempts->save($attempt);
            $context->outcome = Outcome::Challenge;

            return $next($context);
        }

        $skipped = $this->skippedChecks($context);

        if ($skipped !== []) {
            Log::error('Keyring refused to complete a verification because these steps did not run before it: '.implode(', ', $skipped));
            VerificationRefused::dispatch($attempt, $context->factor->key(), $skipped);

            return $context->fail();
        }

        $this->attempts->forget($attempt->purpose);

        $attempt->purpose === Purpose::Login
            ? $this->signIn->complete($context->request, $attempt)
            : $this->signIn->confirm($context->request, $attempt);

        $context->outcome = Outcome::Complete;

        return $next($context);
    }

    /**
     * The final gate: however the steps were arranged, these must have run
     * for this request. A step taken out with dangerouslyReplace() or
     * dangerouslyRemove() has given up its check.
     *
     * @return list<class-string>
     */
    protected function skippedChecks(Context $context): array
    {
        $skipped = [
            EnsureNotThrottled::class => ! $context->throttleChecked,
            VerifyFactor::class => $context->verification === null,
            EnsureNotRiskLocked::class => ! $context->riskLockChecked,
        ] |> array_filter(...) |> array_keys(...);

        return array_values(array_diff($skipped, $this->keyring->dangerouslyChangedSteps()));
    }
}
