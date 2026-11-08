<?php

use Keyring\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';

const CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36';

/**
 * A verified user whose password is "password".
 *
 * @param  array<string, mixed>  $attributes
 */
function taylor(array $attributes = []): User
{
    return User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now(), ...$attributes]);
}

/**
 * What an authenticator app shows for the secret, now or some 30 second
 * steps from now.
 */
function totpCode(string $secret, int $step = 0): string
{
    $engine = app(Google2FA::class);

    return $engine->oathTotp($secret, $engine->getTimestamp() + $step);
}
