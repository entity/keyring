<?php

namespace Keyring\Risk\Signals;

use Keyring\Devices\UserAgent;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;

/**
 * The same session suddenly comes from a different browser. A strong sign the
 * session cookie was stolen. IP changes alone are normal (mobile networks)
 * and don't count.
 */
class SessionFingerprintChanged extends Signal
{
    public function __construct(
        protected int $score = 60,
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        $session = $assessment->session;

        if ($session === null || $session->userAgent === null) {
            return null;
        }

        $before = UserAgent::describe($session->userAgent);
        $now = UserAgent::describe($assessment->request->userAgent());

        return $before !== null && $before !== $now
            ? new Finding('session_fingerprint_changed', $this->score, "The session moved from {$before} to ".($now ?? 'an unknown browser').'.')
            : null;
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Request];
    }
}
