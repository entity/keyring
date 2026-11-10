<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Events\FactorFailed;
use Keyring\Events\FactorVerified;
use Keyring\Events\Lockout;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Pipeline\Context;

/**
 * Identifies the user (for primary factors) and checks the proof. The
 * verifier's timebox is what makes every refusal take the same time.
 */
class VerifyFactor
{
    public function __construct(
        protected AttemptStore $attempts,
        protected KeyringManager $keyring,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $context->request->validate($this->rules($context));

        return $this->verify($context, $next);
    }

    /**
     * Identify the user when the factor starts a login, check the proof, and
     * carry on down the pipeline when it holds.
     */
    protected function verify(Context $context, Closure $next): Context
    {
        // Refused by a rate limit that doesn't say so. Nobody is looked up
        // and no proof is looked at, so the answer can't depend on either.
        // It costs what a check would, and the lockout is reported in here,
        // where a failure would be.
        if ($context->refused) {
            if ($context->factor instanceof PrimaryFactor) {
                $context->factor->stall();
            }

            Lockout::dispatch($context->request, $context->factor->key(), $context->retryAfter);

            return $context->fail();
        }

        if ($context->identifying && $context->factor instanceof PrimaryFactor) {
            $context->authenticator = $this->identify($context->factor, $context->request);

            if ($context->authenticator !== null) {
                $context->attempt = Attempt::start(
                    $context->purpose,
                    $context->authenticator->user(),
                    $context->request->boolean('remember'),
                );
            }
        }

        if ($context->attempt !== null && $context->authenticator !== null) {
            $context->verification = $this->check($context);
        }

        if ($context->verification === null) {
            FactorFailed::dispatch($context->attempt, $context->authenticator, $context->factor->key(), $context->request);

            // Keep factor state, like a code's remaining guesses.
            if (! $context->identifying && $context->attempt !== null) {
                $this->attempts->save($context->attempt);
            }

            return $context->fail();
        }

        $attempt = $context->attempt();
        $attempt->record($context->verification);

        // A factor may verify a different authenticator than the one shown
        // (e.g. the user tapped another of their security keys).
        $authenticator = $context->authenticator();

        if ($context->verification->authenticator !== null && $context->verification->authenticator !== $authenticator->id) {
            $authenticator = $attempt->keyring()->find($context->verification->authenticator) ?? $authenticator;
        }

        $context->authenticator = $authenticator;
        $authenticator->markAsUsed();

        FactorVerified::dispatch($attempt, $authenticator, $context->verification);

        return $next($context);
    }

    /**
     * Who the request is for, when they can be signed in here. Someone the
     * app keeps out costs what checking their proof would have, and the
     * attempt carries on as if nobody was found.
     */
    protected function identify(PrimaryFactor $factor, Request $request): ?Authenticator
    {
        $authenticator = $factor->identify($request);

        if ($authenticator === null || $this->maySignIn($authenticator->user())) {
            return $authenticator;
        }

        $factor->stall();

        return null;
    }

    /**
     * Whether whoever the factor found can be signed in here.
     */
    protected function maySignIn(?Authenticatable $user): bool
    {
        return $user instanceof Model && $this->keyring->belongsToGuard($user) && $this->keyring->allowsSignIn($user);
    }

    /**
     * Check the proof in the request. Null when it doesn't match.
     */
    protected function check(Context $context): ?Verification
    {
        // On a challenge or a step-up nobody was identified, so a factor
        // whose proof is who identify() found has nothing to check.
        if (! $context->identifying && $context->factor instanceof PrimaryFactor && ! $context->factor->answersChallenges()) {
            return null;
        }

        return $context->factor->verify($context->attempt(), $context->authenticator(), $context->request);
    }

    /**
     * @return array<string, mixed>
     */
    protected function rules(Context $context): array
    {
        return [
            ...($context->identifying && $context->factor instanceof PrimaryFactor ? $context->factor->identificationRules() : []),
            ...$context->factor->rules(),
        ];
    }
}
