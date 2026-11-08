<?php

namespace Keyring\Http\Controllers;

use Illuminate\Cache\RateLimiter;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\SendsCodes;
use Keyring\Enums\Purpose;
use Keyring\Events\FactorChallenged;
use Keyring\Http\Controllers\Concerns\RespondsToVerification;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Login\StepUp;
use Keyring\Models\Authenticator;
use Keyring\Pipeline\Context;

/**
 * One controller for every factor and every purpose (login, step-up,
 * recovery). Adding a factor never needs a new route.
 */
class ChallengeController
{
    use RespondsToVerification, RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected AttemptStore $attempts,
        protected StepUp $stepUp,
    ) {}

    public function show(Request $request, ?string $factor = null): mixed
    {
        $purpose = $this->purpose($request);
        $attempt = $this->attempts->current($purpose)
            ?? ($purpose === Purpose::Confirm ? $this->stepUp->begin($request, Requirement::aal1(), building: false) : null);

        if ($attempt === null) {
            return $this->expired($purpose);
        }

        $options = $attempt->options();

        if ($options->isEmpty()) {
            $this->attempts->forget($purpose);

            return $this->expired($purpose, __('keyring::keyring.unavailable'));
        }

        $authenticator = $this->choose($attempt, $options, $factor, $request->query('authenticator'));

        if ($authenticator === null) {
            return to_route("keyring.{$purpose->value}.challenge");
        }

        $attempt->present($authenticator);
        $challenge = $authenticator->factor()->challenge($attempt, $authenticator);
        $this->attempts->save($attempt);

        FactorChallenged::dispatch($attempt, $authenticator);

        return $this->keyring->render($purpose === Purpose::Login ? 'challenge' : $purpose->value, [
            'purpose' => $purpose->value,
            'factor' => $authenticator->factor,
            'authenticator' => $authenticator->factor()->present($authenticator),
            'challenge' => $challenge,
            'alternatives' => $options
                ->reject(fn (Authenticator $option) => $option->id === $authenticator->id)
                ->map(fn (Authenticator $option) => $option->factor()->present($option))
                ->values()
                ->all(),
            'canTrustDevice' => $purpose === Purpose::Login && config('keyring.devices.trust_for') !== null,
            'expiresAt' => date(DATE_ATOM, $attempt->expiresAt),
        ]);
    }

    /**
     * Send a code for factors that need one. Separate from viewing the page,
     * so prefetching or reloading never sends anything.
     */
    public function send(Request $request, RateLimiter $limiter, string $factor): mixed
    {
        $purpose = $this->purpose($request);
        $attempt = $this->attempts->current($purpose);

        if ($attempt === null) {
            return $this->expired($purpose);
        }

        $factor = $this->keyring->factor($factor);
        abort_unless($factor instanceof SendsCodes, 404);

        $authenticator = $this->authenticatorFor($request, $attempt, $factor->key()) ?? abort(404);
        $key = 'keyring-send:'.$attempt->id;

        // Three codes per sign in attempt every ten minutes.
        if (! $limiter->attempt($key, 3, fn () => $factor->send($attempt, $authenticator), 600)) {
            throw ValidationException::withMessages([
                'code' => __('auth.throttle', ['seconds' => $limiter->availableIn($key), 'minutes' => ceil($limiter->availableIn($key) / 60)]),
            ])->status(429);
        }

        $this->attempts->save($attempt);

        return $this->status('code-sent');
    }

    public function verify(Request $request, string $factor): mixed
    {
        $purpose = $this->purpose($request);
        $attempt = $this->attempts->current($purpose);

        if ($attempt === null) {
            return $this->expired($purpose);
        }

        $factor = $this->keyring->factor($factor);
        $authenticator = $this->authenticatorFor($request, $attempt, $factor->key());

        return $this->verifyAndRespond(new Context($request, $purpose, $factor, $attempt, $authenticator));
    }

    /**
     * The authenticator a request is aimed at: the one it names, the one the
     * page showed, or the only one of that factor.
     */
    protected function authenticatorFor(Request $request, Attempt $attempt, string $factor): ?Authenticator
    {
        return $this->pick($attempt, $attempt->options(), $factor, $request->input('authenticator'), strict: true);
    }

    /**
     * The authenticator to show: the one asked for, else the default.
     *
     * @param  Collection<int, Authenticator>  $options
     */
    protected function choose(Attempt $attempt, Collection $options, ?string $factor, mixed $id): ?Authenticator
    {
        return $factor === null
            ? $options->firstWhere('is_default', true) ?? $options->first()
            : $this->pick($attempt, $options, $factor, $id, strict: false);
    }

    /**
     * The option with the given (or last presented) ID for the factor. With
     * no match, showing a page can fall back to the first, but verifying only
     * falls back when there's no doubt which one is meant.
     *
     * @param  Collection<int, Authenticator>  $options
     */
    protected function pick(Attempt $attempt, Collection $options, string $factor, mixed $id, bool $strict): ?Authenticator
    {
        $candidates = $options->where('factor', $factor);

        return $candidates->firstWhere('id', $id ?? $attempt->presented($factor))
            ?? (! $strict || $candidates->count() === 1 ? $candidates->first() : null);
    }

    /**
     * The purpose comes from the route name: keyring.{purpose}.challenge.
     */
    protected function purpose(Request $request): Purpose
    {
        return Purpose::from(Str::between((string) $request->route()?->getName(), 'keyring.', '.'));
    }

    protected function expired(Purpose $purpose, ?string $message = null): RedirectResponse
    {
        return to_route($purpose === Purpose::Login ? 'login' : 'keyring.confirm.challenge')
            ->withErrors([config('keyring.username') => $message ?? __('keyring::keyring.expired')]);
    }
}
