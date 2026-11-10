<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Timebox;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Events\FactorFailed;
use Keyring\Events\FactorVerified;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Verification;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Support\Duration;

/**
 * Identifies the user (for primary factors) and checks the proof, inside a
 * timebox so every refusal takes the same time: a wrong proof, an unknown
 * user, or a right proof a later step turns down.
 */
class VerifyFactor
{
    public function __construct(
        protected Container $container,
        protected AttemptStore $attempts,
        protected KeyringManager $keyring,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $context->request->validate($this->rules($context));

        // The timebox stays open until the attempt is answered, not just
        // until the proof is checked: a right password refused further on,
        // by a risk lock say, has to take as long as a wrong one.
        return $this->container->make(Timebox::class)->call(function (Timebox $timebox) use ($context, $next) {
            $context = $this->verify($context, $next);

            if (in_array($context->outcome, [Outcome::Challenge, Outcome::Complete], true)) {
                $timebox->returnEarly();
            }

            return $context;
        }, Duration::milliseconds(config('keyring.timebox')) * 1000);
    }

    /**
     * Identify the user when the factor starts a login, check the proof, and
     * carry on down the pipeline when it holds.
     */
    protected function verify(Context $context, Closure $next): Context
    {
        if ($context->identifying && $context->factor instanceof PrimaryFactor) {
            $authenticator = $context->factor->identify($context->request);

            $context->authenticator = $authenticator !== null && $this->maySignIn($authenticator->user()) ? $authenticator : null;

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
     * Whether whoever the factor found can be signed in here. When they
     * can't, the attempt carries on as if nobody was found.
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
