<?php

namespace Keyring\Risk;

use Closure;
use Illuminate\Contracts\Container\Container;
use Keyring\Contracts\Signal;
use Keyring\Risk\Signals\ImpossibleTravel;
use Keyring\Risk\Signals\NewCountry;
use Keyring\Risk\Signals\NewDevice;
use Keyring\Risk\Signals\RecentlyChangedRecovery;
use Keyring\Risk\Signals\RepeatedFactorFailures;
use Keyring\Risk\Signals\SessionFingerprintChanged;

/**
 * Runs signals and decides what to do about the result.
 *
 *     Keyring::risk([NewDevice::class, ImpossibleTravel::class])
 *         ->respond(fn (Risk $risk, Checkpoint $at) => match ($risk->level) { ... });
 */
class RiskEngine
{
    /** @var list<class-string<Signal>|Signal> */
    protected array $signals = [
        NewDevice::class,
        NewCountry::class,
        ImpossibleTravel::class,
        RepeatedFactorFailures::class,
        RecentlyChangedRecovery::class,
        SessionFingerprintChanged::class,
    ];

    /** @var (Closure(Risk, Checkpoint): Action)|null */
    protected ?Closure $responder = null;

    public function __construct(
        protected Container $container,
    ) {}

    /**
     * @param  list<class-string<Signal>|Signal>  $signals
     */
    public function signals(array $signals): static
    {
        $this->signals = $signals;

        return $this;
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
        $findings = [];

        foreach ($this->signals as $signal) {
            $signal = $signal instanceof Signal ? $signal : $this->container->make($signal);

            if (in_array($assessment->checkpoint, $signal->checkpoints(), true) && $finding = $signal->assess($assessment)) {
                $findings[] = $finding;
            }
        }

        return new Risk($findings);
    }

    public function decide(Risk $risk, Checkpoint $checkpoint): Action
    {
        if ($this->responder !== null) {
            return ($this->responder)($risk, $checkpoint);
        }

        return match ($risk->level) {
            Level::Low => Action::allow(),
            Level::Medium => Action::stepUp(),
            Level::High => Action::stepUp()->notify(),
            Level::Critical => Action::deny()->revokeAllSessions()->notify(),
        };
    }

    public function hasRequestSignals(): bool
    {
        foreach ($this->signals as $signal) {
            $signal = $signal instanceof Signal ? $signal : $this->container->make($signal);

            if (in_array(Checkpoint::Request, $signal->checkpoints(), true)) {
                return true;
            }
        }

        return false;
    }
}
