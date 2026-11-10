<?php

namespace Keyring\Risk;

use Closure;
use Illuminate\Container\Attributes\Singleton;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Container\Container;
use Keyring\Contracts\Signal;
use Keyring\Events\RiskAssessed;
use Keyring\Risk\Signals\ImpossibleTravel;
use Keyring\Risk\Signals\NewDevice;
use Keyring\Sessions\Sessions;

/**
 * Runs signals and decides what to do about the result.
 *
 *     Keyring::risk()->signals([NewDevice::class, ImpossibleTravel::class])
 *         ->respond(fn (Risk $risk, Checkpoint $at) => match ($risk->level) { ... });
 */
#[Singleton]
class RiskEngine
{
    /**
     * None until the app picks some with Keyring::risk()->signals([...]).
     *
     * @var list<class-string<Signal>|Signal>
     */
    protected array $signals = [];

    /** @var (Closure(Risk, Checkpoint): Action)|null */
    protected ?Closure $responder = null;

    /** @var list<Signal>|null */
    protected ?array $resolved = null;

    public function __construct(
        protected Container $container,
    ) {}

    /**
     * Replace the signals.
     *
     * @param  list<class-string<Signal>|Signal>  $signals
     */
    public function signals(array $signals): static
    {
        $this->signals = $signals;
        $this->resolved = null;

        return $this;
    }

    /**
     * Add signals to the ones already on.
     *
     * @param  class-string<Signal>|Signal  ...$signals
     */
    public function push(string|Signal ...$signals): static
    {
        return $this->signals([...$this->signals, ...array_values($signals)]);
    }

    /**
     * @param  Closure(Risk, Checkpoint): Action  $responder
     */
    public function respond(Closure $responder): static
    {
        $this->responder = $responder;

        return $this;
    }

    public function assess(Assessment $assessment): Risk
    {
        $findings = array_map(
            fn (Signal $signal) => $signal->assess($assessment),
            $this->signalsFor($assessment->checkpoint),
        );

        return new Risk($findings |> array_filter(...) |> array_values(...));
    }

    public function decide(Risk $risk, Checkpoint $checkpoint): Action
    {
        $action = $this->responder !== null
            ? ($this->responder)($risk, $checkpoint)
            : match ($risk->level) {
                Level::Low => Action::allow(),
                Level::Medium => Action::stepUp(),
                Level::High => Action::stepUp()->notify(),
                Level::Critical => Action::deny()->revokeAllSessions()->notify(),
            };

        // A login attempt hasn't proved who's behind it. If it could revoke
        // anything, someone with only the password could sign the owner out
        // as often as they liked.
        return $checkpoint === Checkpoint::Login ? $action->withoutRevokingSessions() : $action;
    }

    /**
     * Decide what to do about the risk and carry out the parts that don't
     * depend on where we are: announce it, sign out everywhere, lock. The
     * caller handles deny, step-up and re-authentication.
     */
    public function enforce(Authenticatable $user, Risk $risk, Checkpoint $checkpoint): Action
    {
        $action = $this->decide($risk, $checkpoint);

        if ($action->doesSomething()) {
            RiskAssessed::dispatch($user, $risk, $action, $checkpoint);
        }

        if ($action->revokeSessions) {
            $this->container->make(Sessions::class)->signOutEverywhere($user);
        }

        if ($action->lockSeconds !== null) {
            // Like revoking sessions, a login attempt may not cost the owner
            // their trusted devices: the lock already refuses every sign in.
            if ($checkpoint !== Checkpoint::Login) {
                $this->container->make(Sessions::class)->distrustDevices($user);
            }

            $this->container->make(RiskLocks::class)->lock($user, $action->lockSeconds);
        }

        return $action;
    }

    /**
     * @return list<Signal>
     */
    public function signalsFor(Checkpoint $checkpoint): array
    {
        $this->resolved ??= array_map(
            fn (string|Signal $signal) => $signal instanceof Signal ? $signal : $this->container->make($signal),
            $this->signals,
        );

        return array_values(array_filter($this->resolved, fn (Signal $signal) => in_array($checkpoint, $signal->checkpoints(), true)));
    }
}
