<?php

namespace Keyring\Factors;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Contracts\Enrollable;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
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
class Totp extends Factor implements Enrollable
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

        $used = $timestep !== false && $this->consume($authenticator, function (Authenticator $locked) use ($timestep) {
            if ((int) $timestep <= (int) $locked->meta('last_timestep', 0)) {
                return false;
            }

            $locked->withMeta('last_timestep', (int) $timestep);

            return true;
        });

        return $used ? $this->verified($authenticator) : null;
    }

    public function beginEnrollment(Authenticatable&Model $user, Request $request): Enrollment
    {
        $secret = $this->engine->generateSecretKey(32);
        $url = $this->engine->getQRCodeUrl(config('app.name'), (string) $user->getAttribute(Keyring::username()), $secret);

        return Enrollment::make($this->key(), [
            'secret' => $secret,
            'url' => $url,
            'qr' => $this->qr($url),
        ], [
            'secret' => $secret,
            'name' => $request->string('name')->trim()->limit(64, '')->toString() ?: __('Authenticator app'),
        ]);
    }

    public function enrollmentRules(): array
    {
        return $this->rules();
    }

    public function confirmEnrollment(Authenticatable&Model $user, Enrollment $enrollment, Request $request): ?Authenticator
    {
        $code = $this->normalizeCode((string) $request->input('code'));
        $timestep = ctype_digit($code)
            ? $this->engine->verifyKeyNewer($enrollment->state('secret'), $code, 0, $this->window)
            : false;

        if ($timestep === false) {
            return null;
        }

        return $this->makeAuthenticator([
            'name' => $enrollment->state('name'),
            'secret' => $enrollment->state('secret'),
            'meta' => ['last_timestep' => (int) $timestep],
        ]);
    }

    protected function qr(string $url): string
    {
        $svg = new Writer(new ImageRenderer(new RendererStyle(192, 0), new SvgImageBackEnd))->writeString($url);

        return trim(substr($svg, strpos($svg, "\n") + 1));
    }

    public function engine(): Google2FA
    {
        return $this->engine;
    }
}
