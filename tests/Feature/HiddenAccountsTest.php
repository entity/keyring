<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Notification;
use Keyring\Changes\EmailChanges;
use Keyring\Enums\Assurance;
use Keyring\Enums\EmailConfirmation;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Tests\Fixtures\SingleSignOn;
use Keyring\Tests\Fixtures\User;

// An app can hide accounts with a global scope of its own: suspended ones,
// or every tenant's but the current one. Keyring's records for them are
// still there, and what reaches one has to treat its owner as nobody.
beforeEach(function () {
    $this->user = taylor();

    $this->hide = function () {
        $this->user->forceFill(['name' => 'Hidden'])->saveQuietly();

        User::addGlobalScope('hidden', fn (Builder $query) => $query->where('name', '!=', 'Hidden'));
    };
});

afterEach(fn () => Model::clearBootedModels());

it('answers a factor of the app\'s own that finds a hidden account like one that finds nobody', function () {
    // A badge the door reader vouched for, found by the authenticator stored for it.
    Keyring::factors([Password::class, new class extends SingleSignOn
    {
        public function key(): string
        {
            return 'badge';
        }

        public function identify(Request $request): ?Authenticator
        {
            return Authenticator::query()->where('factor', 'badge')->first();
        }
    }]);

    Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'badge', 'name' => 'Badge', 'secret' => null]);

    ($this->hide)();

    $this->postJson(route('keyring.login.factor', 'badge'))->assertStatus(422);
    $this->assertGuest();
});

it('does not record a press on an email change link it then calls invalid', function () {
    Notification::fake();
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2)->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();
    $change = PendingChange::sole();
    $token = 'the-token-the-new-address-was-sent';
    $change->forceFill(['confirm_token' => PendingChange::hashToken($token), 'current_token' => null])->save();

    ($this->hide)();

    expect(app(EmailChanges::class)->confirm($change->fresh(), $token))->toBe(EmailConfirmation::Invalid)
        ->and($change->fresh()->confirmed_at)->toBeNull();
});
