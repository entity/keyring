<?php

declare(strict_types=1);

use Keyring\Sso\HostResolver;
use Keyring\Testing\FakeIdentityProvider;

it('answers from the list it was faked with, and nothing for a name not on it', function () {
    $resolver = HostResolver::fake(['idp.example.com' => ['93.184.216.34', '::1']]);

    expect(app(HostResolver::class))->toBe($resolver)
        ->and($resolver->addresses('idp.example.com'))->toBe(['93.184.216.34', '::1'])
        ->and($resolver->addresses('other.example.com'))->toBe([]);
});

it('is faked by the fake identity provider, so its hosts are never looked up', function () {
    app()->forgetInstance(HostResolver::class);

    new FakeIdentityProvider;

    expect(app()->bound(HostResolver::class))->toBeTrue()
        ->and(app(HostResolver::class)->addresses('idp.test'))->toBe([]);
});

it('keeps a fake the test already set up when the fake identity provider is made', function () {
    HostResolver::fake(['idp.test' => ['10.0.0.1']]);

    new FakeIdentityProvider;

    expect(app(HostResolver::class)->addresses('idp.test'))->toBe(['10.0.0.1']);
});

it('looks each name up once for as long as it lives', function () {
    $lookups = 0;
    $resolver = new HostResolver(function (string $host) use (&$lookups) {
        $lookups++;

        return ['93.184.216.34'];
    });

    expect($resolver->addresses('idp.example.com'))->toBe(['93.184.216.34'])
        ->and($resolver->addresses('idp.example.com'))->toBe(['93.184.216.34'])
        ->and($lookups)->toBe(1)
        ->and($resolver->addresses('other.example.com'))->toBe(['93.184.216.34'])
        ->and($lookups)->toBe(2);
});

it('is one resolver for the whole of a request', function () {
    app()->forgetInstance(HostResolver::class);
    $resolver = app(HostResolver::class);

    expect(app(HostResolver::class))->toBe($resolver);

    app()->forgetScopedInstances();

    expect(app(HostResolver::class))->not->toBe($resolver);
});
