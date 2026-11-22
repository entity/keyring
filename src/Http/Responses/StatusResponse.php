<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\Responses\StatusResponse as StatusResponseContract;
use Keyring\Facades\Keyring;
use Keyring\Support\EncryptedSession;

class StatusResponse implements StatusResponseContract
{
    use ChoosesFormat;

    /**
     * Where a non-JSON response flashes its data, encrypted.
     */
    public const string RESULT = 'keyring.result';

    /**
     * The pages a status can send the user on to, by route name.
     */
    protected const array PAGES = [
        'login' => 'login',
        'register' => 'register',
        'password.request' => 'forgot-password',
        'verification.notice' => 'verify-email',
        'keyring.login.challenge' => 'challenge',
        'keyring.confirm.challenge' => 'confirm',
    ];

    /**
     * @param  string  $status  a slug such as "device-revoked", with its message in keyring::status
     * @param  array<string, mixed>  $data
     * @param  string|null  $redirect  where to go instead of back
     */
    public function __construct(
        public readonly string $status,
        public readonly array $data = [],
        public readonly ?string $redirect = null,
    ) {}

    public function toResponse($request)
    {
        if ($this->wantsJson($request)) {
            return new JsonResponse(Arr::whereNotNull([
                'status' => $this->status,
                'message' => Keyring::statusMessage($this->status),
                'page' => $this->page(),
                'redirect' => $this->redirect,
                ...$this->data,
            ]));
        }

        // Extra data goes under keyring.result: flashing "keyring" itself would
        // replace the session's verifications and registry ID. It can hold a
        // secret being set up or new recovery codes, so it's encrypted like
        // the enrollment it came from, whatever the session driver. Pages
        // read it back with Keyring::result().
        if ($this->data !== []) {
            app(EncryptedSession::class)->flash(self::RESULT, $this->data);
        }

        return ($this->redirect === null ? back() : redirect($this->redirect))->with('status', $this->status);
    }

    /**
     * The name of Keyring's page the redirect goes to, such as "login", for
     * a frontend whose pages aren't at Keyring's URLs. Null when it goes
     * anywhere else, such as home.
     */
    protected function page(): ?string
    {
        foreach (self::PAGES as $route => $page) {
            if ($this->redirect !== null && Route::has($route) && route($route) === $this->redirect) {
                return $page;
            }
        }

        return null;
    }
}
