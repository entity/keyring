<?php

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Support\Facades\Notification;
use Keyring\Enums\Assurance;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Models\PendingChange;

// An app whose users sign in with a handle and have an email address too.
beforeEach(function () {
    config(['keyring.username' => 'name', 'keyring.email' => 'email']);
    Notification::fake();

    $this->user = taylor(['name' => 'taylor']);
});

it('signs in with the username, and reports failures on it', function () {
    $this->post('/login', ['name' => 'taylor', 'password' => 'nope'])->assertSessionHasErrors('name');
    $this->post('/login', ['name' => 'Taylor', 'password' => 'password'])->assertRedirect('/dashboard');
});

it('resets a password by email address', function () {
    $this->post(route('password.email'), ['email' => 'taylor@example.com'])->assertSessionHasNoErrors();

    Notification::assertSentTo($this->user, ResetPassword::class, function (ResetPassword $notification) {
        $url = $notification->toMail($this->user)->actionUrl;

        expect($url)->toContain('email=taylor%40example.com');

        $this->post(route('password.update'), [
            'token' => $notification->token,
            'email' => 'taylor@example.com',
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ])->assertSessionHasNoErrors();

        return true;
    });

    $this->post('/login', ['name' => 'taylor', 'password' => 'correct horse battery staple'])->assertRedirect('/dashboard');
});

it('changes and protects the email address, not the username', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])
        ->assertOk();

    expect(PendingChange::sole()->attribute)->toBe('email');

    $this->user->update(['name' => 'otwell']);

    expect(fn () => $this->user->update(['email' => 'other@example.com']))->toThrow(ProtectedAttributeException::class);
});
