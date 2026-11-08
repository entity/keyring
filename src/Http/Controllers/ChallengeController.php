<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Keyring\Enums\Purpose;
use Keyring\Events\FactorChallenged;
use Keyring\Http\Controllers\Concerns\RespondsToVerification;
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
    use RespondsToVerification;

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
            return redirect()->route("keyring.{$purpose->value}.challenge");
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
            'expiresAt' => date(DATE_ATOM, $attempt->expiresAt),
        ]);
    }

    public function verify(Request $request, string $factor): mixed
    {
        $purpose = $this->purpose($request);
        $attempt = $this->attempts->current($purpose);

        if ($attempt === null) {
            return $this->expired($purpose);
        }

        $factor = $this->keyring->hasFactor($factor) ? $this->keyring->factor($factor) : abort(404);
        $options = $attempt->options()->where('factor', $factor->key());

        $authenticator = $options->first(
            fn (Authenticator $option) => $option->id === ($request->input('authenticator') ?? $attempt->presented($factor->key())),
        ) ?? ($options->count() === 1 ? $options->first() : null);

        return $this->verifyAndRespond(new Context($request, $purpose, $factor, $attempt, $authenticator));
    }

    /**
     * @param  Collection<int, Authenticator>  $options
     */
    protected function choose(Attempt $attempt, Collection $options, ?string $factor, mixed $id): ?Authenticator
    {
        if ($factor === null) {
            return $options->first(fn (Authenticator $option) => $option->is_default) ?? $options->first();
        }

        $candidates = $options->where('factor', $factor);

        return $candidates->first(fn (Authenticator $option) => $option->id === ($id ?? $attempt->presented($factor)))
            ?? $candidates->first();
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
        return redirect()
            ->route($purpose === Purpose::Login ? 'login' : 'keyring.confirm.challenge')
            ->withErrors([config('keyring.username') => $message ?? __('keyring::keyring.expired')]);
    }
}
