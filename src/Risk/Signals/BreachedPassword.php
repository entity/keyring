<?php

declare(strict_types=1);

namespace Keyring\Risk\Signals;

use Illuminate\Contracts\Validation\UncompromisedVerifier;
use Keyring\Factors\Password;
use Keyring\Login\Verification;
use Keyring\Risk\Assessment;
use Keyring\Risk\Finding;
use Keyring\Support\Input;
use Keyring\Support\PasswordRules;

/**
 * The password that was just used appears in known breaches (Have I Been
 * Pwned, via k-anonymity, so the password never leaves the server). Makes a
 * network call at sign in, so it isn't on by default. Keyring's own response
 * to it holds the user until they choose another (RiskEngine).
 */
class BreachedPassword extends Signal
{
    /** What its finding is called, in Risk::has() and a password hold's reason. */
    public const string FINDING = 'breached_password';

    public function __construct(
        protected UncompromisedVerifier $verifier,
        protected int $score = 40,
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        $verifications = $assessment->attempt->verifications ?? [];
        $usedPassword = array_any($verifications, fn (Verification $verification) => $verification->factor === Password::KEY);
        $password = Input::get($assessment->request, 'password');

        if (! $usedPassword || ! is_string($password)) {
            return null;
        }

        // As it was hashed, which is the form a breach list would have too.
        return $this->verifier->verify(['value' => PasswordRules::normalize($password), 'threshold' => 0])
            ? null
            : new Finding(self::FINDING, $this->score, 'The password appears in a known data breach.');
    }
}
