<?php

declare(strict_types=1);

use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Login\Verification;
use Keyring\Sessions\SessionAssurance;

/**
 * @param  list<Verification>  $verifications
 */
function proved(array $verifications, ?Assurance $signedIn = null): SessionAssurance
{
    session()->put(SessionAssurance::KEY, collect($verifications)->mapWithKeys(fn (Verification $verification) => [$verification->factor => $verification->toArray()])->all());

    if ($signedIn !== null) {
        session()->put(SessionAssurance::SIGNED_IN, $signedIn->value);
    }

    return app(SessionAssurance::class);
}

describe('lowering to aal1', function () {
    it('keeps what isn\'t something the user has, whichever was proved first', function () {
        $assurance = proved([
            new Verification(Totp::KEY, null, [Category::Possession], at: now()->getTimestamp()),
            new Verification(Password::KEY, null, [Category::Knowledge], at: now()->getTimestamp()),
            new Verification(EmailCode::KEY, null, [Category::Address], at: now()->getTimestamp()),
            new Verification(RecoveryCodes::KEY, null, [Category::Possession], at: now()->getTimestamp()),
        ], Assurance::AAL2);

        $assurance->lowerToAal1();

        expect(array_column($assurance->all(), 'factor'))->toBe([Password::KEY, EmailCode::KEY])
            ->and($assurance->level())->toBe(Assurance::AAL1)
            ->and($assurance->signedInLevel())->toBe(Assurance::AAL1);
    });

    it('keeps a session short of aal2 as it was', function () {
        $assurance = proved([new Verification(Totp::KEY, null, [Category::Possession], at: now()->getTimestamp())]);

        $assurance->lowerToAal1();

        expect(array_column($assurance->all(), 'factor'))->toBe([Totp::KEY])
            ->and($assurance->level())->toBe(Assurance::AAL1)
            ->and($assurance->signedInLevel())->toBe(Assurance::None);
    });

    // What's kept has lapsed at AAL1, so the session no longer holds the
    // level it would be brought down to.
    it('forgets the level it signed in at when what\'s kept no longer holds aal1', function () {
        config(['keyring.sessions.levels.aal1.absolute' => '1h']);
        $assurance = proved([
            new Verification(Password::KEY, null, [Category::Knowledge], at: now()->subHours(2)->getTimestamp()),
            new Verification(Totp::KEY, null, [Category::Possession], at: now()->getTimestamp()),
        ], Assurance::AAL1);

        $assurance->lowerToAal1();

        expect(session()->has(SessionAssurance::SIGNED_IN))->toBeFalse()
            ->and($assurance->level())->toBe(Assurance::None);
    });
});
