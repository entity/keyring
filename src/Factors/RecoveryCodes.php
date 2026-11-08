<?php

namespace Keyring\Factors;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Keyring\Enums\Category;
use Keyring\Events\RecoveryCodeUsed;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * Single-use codes the user saved when setting up their first second factor.
 * Stored as keyed hashes, never in plain text.
 */
class RecoveryCodes extends Factor
{
    public function __construct(
        protected int $count = 8,
    ) {}

    public function key(): string
    {
        return 'recovery';
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Possession];
    }

    /**
     * Always offered last.
     */
    public function priority(): int
    {
        return 0;
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $hash = $this->hash((string) $request->input('code'));
        $hashes = $this->hashes($authenticator);

        $match = array_find_key($hashes, fn (string $stored) => hash_equals($stored, $hash));

        if ($match === null) {
            return null;
        }

        unset($hashes[$match]);
        $authenticator->secret = json_encode(array_values($hashes));
        $authenticator->save();

        RecoveryCodeUsed::dispatch($authenticator, count($hashes));

        return $this->verified($authenticator);
    }

    public function present(Authenticator $authenticator): array
    {
        return [...parent::present($authenticator), 'remaining' => count($this->hashes($authenticator))];
    }

    /**
     * Make a fresh set of codes. Returns the plain codes to show the user once,
     * and the secret to store.
     *
     * @return array{codes: list<string>, secret: string}
     */
    public function generate(): array
    {
        $codes = array_map(
            fn () => Str::lower(Str::random(5).'-'.Str::random(5)),
            range(1, $this->count),
        );

        return ['codes' => $codes, 'secret' => $this->secretFor($codes)];
    }

    /**
     * The value to store for a set of plain codes.
     *
     * @param  list<string>  $codes
     */
    public function secretFor(array $codes): string
    {
        return json_encode(array_map($this->hash(...), $codes));
    }

    /**
     * @return list<string>
     */
    protected function hashes(Authenticator $authenticator): array
    {
        return json_decode($authenticator->secret ?? '[]', true) ?: [];
    }

    protected function hash(string $code): string
    {
        return hash_hmac('sha256', Str::lower($this->normalizeCode($code)), config('app.key'));
    }
}
