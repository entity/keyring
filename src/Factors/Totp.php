<?php

namespace Keyring\Factors;

use Illuminate\Http\Request;
use Keyring\Enums\Category;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use PragmaRX\Google2FA\Google2FA;

/**
 * Time-based one-time passwords from an authenticator app (RFC 6238).
 *
 * The last accepted time step is stored on the authenticator, so a code can't
 * be replayed within its window.
 */
class Totp extends Factor
{
    public function __construct(
        protected Google2FA $engine,
        protected int $window = 1,
    ) {}

    public function key(): string
    {
        return 'totp';
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Possession];
    }

    public function priority(): int
    {
        return 60;
    }

    public function rules(): array
    {
        return ['code' => ['required', 'string', 'max:16']];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $code = $this->normalizeCode((string) $request->input('code'));

        if ($authenticator->secret === null || ! ctype_digit($code)) {
            return null;
        }

        $timestep = $this->engine->verifyKeyNewer(
            $authenticator->secret,
            $code,
            (int) $authenticator->meta('last_timestep', 0),
            $this->window,
        );

        if ($timestep === false) {
            return null;
        }

        $authenticator->withMeta('last_timestep', (int) $timestep)->save();

        return $this->verified($authenticator);
    }

    public function engine(): Google2FA
    {
        return $this->engine;
    }
}
