<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\UserKeyring;

// What apps build on, as the README's "What's Stable" lists it: the route
// names, the middleware aliases, the methods of the Keyring facade and of
// Keyring::for($user), the contracts, the events and the email types. A
// rename here breaks every app that uses it, and nothing else would notice
// when the tests are renamed with it.
//
// A change that's meant: run UPDATE_PUBLIC_API=1 vendor/bin/pest
// tests/Feature/PublicApiTest.php, commit tests/Fixtures/public-api.json
// with it, and say so in UPGRADE.md.
it('keeps the names apps build on, or says which changed', function () {
    withFeatures(Features::all());

    $methods = fn (string $class) => collect(new ReflectionClass($class)->getMethods(ReflectionMethod::IS_PUBLIC))
        ->reject(fn (ReflectionMethod $method) => $method->isConstructor() || Str::startsWith($method->getName(), '__'))
        ->map(fn (ReflectionMethod $method) => $method->getName())
        ->sort()->values()->all();

    $classes = fn (string $directory, string $namespace) => collect(File::allFiles(__DIR__.'/../../src/'.$directory))
        ->map(fn (SplFileInfo $file) => $namespace.'\\'.str_replace('/', '\\', Str::beforeLast($file->getRelativePathname(), '.php')))
        ->sort()->values();

    $api = [
        'routes' => collect(app('router')->getRoutes()->getRoutes())
            ->filter(fn ($route) => $route->getName() !== null)
            ->mapWithKeys(fn ($route) => [$route->getName() => implode('|', array_diff($route->methods(), ['HEAD'])).' /'.ltrim($route->uri(), '/')])
            ->sortKeys()->all(),
        'middleware' => collect(app('router')->getMiddleware())->keys()->filter(fn (string $alias) => Str::startsWith($alias, 'keyring'))->sort()->values()->all(),
        'features' => Features::all(),
        'emails' => KeyringManager::NOTIFICATIONS,
        'facade' => $methods(KeyringManager::class),
        'user' => $methods(UserKeyring::class),
        'contracts' => $classes('Contracts', 'Keyring\\Contracts')->mapWithKeys(fn (string $contract) => [$contract => $methods($contract)])->all(),
        'events' => $classes('Events', 'Keyring\\Events')->mapWithKeys(fn (string $event) => [
            $event => collect(new ReflectionClass($event)->getProperties(ReflectionProperty::IS_PUBLIC))->map->getName()->sort()->values()->all(),
        ])->all(),
    ];

    $path = __DIR__.'/../Fixtures/public-api.json';

    if (getenv('UPDATE_PUBLIC_API')) {
        File::put($path, json_encode($api, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
    }

    expect($api)->toEqual(json_decode(File::get($path), true, flags: JSON_THROW_ON_ERROR));
});
