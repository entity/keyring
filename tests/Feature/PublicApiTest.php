<?php

declare(strict_types=1);

use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\UserKeyring;

// What apps build on, as the README's "What's Stable" lists it: the config
// options and what each is until an app sets it, the route names, the
// middleware aliases, the methods of the Keyring facade, of
// Keyring::for($user) and of the contracts, each with its parameters and
// return type, the events and the email types. A rename, a new type or a
// new default here changes every app that uses it, and nothing else would
// notice when the tests are changed with it.
//
// A change that's meant: run UPDATE_PUBLIC_API=1 vendor/bin/pest
// tests/Feature/PublicApiTest.php, commit tests/Fixtures/public-api.json
// with it, and say so in UPGRADE.md.
it('keeps the names and defaults apps build on, or says which changed', function () {
    withFeatures(Features::all());

    // Each method as it would be declared, so a new type, parameter or
    // default shows here as well as a new name: revoke(string $id):
    // ?Keyring\Sessions\RegisteredSession.
    $export = fn (mixed $value): string => match (true) {
        $value === null => 'null',
        $value instanceof UnitEnum => $value::class.'::'.$value->name,
        is_array($value) => json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
        default => var_export($value, true),
    };

    $default = fn (ReflectionParameter $parameter) => match (true) {
        ! $parameter->isDefaultValueAvailable() => '',
        $parameter->isDefaultValueConstant() => ' = '.$parameter->getDefaultValueConstantName(),
        default => ' = '.$export($parameter->getDefaultValue()),
    };

    $parameter = fn (ReflectionParameter $parameter) => ltrim(implode(' ', [
        (string) $parameter->getType(),
        ($parameter->isPassedByReference() ? '&' : '').($parameter->isVariadic() ? '...' : '').'$'.$parameter->getName(),
    ])).$default($parameter);

    $methods = fn (string $class) => collect(new ReflectionClass($class)->getMethods(ReflectionMethod::IS_PUBLIC))
        ->reject(fn (ReflectionMethod $method) => $method->isConstructor() || Str::startsWith($method->getName(), '__'))
        ->sortBy(fn (ReflectionMethod $method) => $method->getName())
        ->map(fn (ReflectionMethod $method) => ($method->isStatic() ? 'static ' : '')
            .($method->returnsReference() ? '&' : '')
            .$method->getName()
            .'('.collect($method->getParameters())->map($parameter)->implode(', ').')'
            .($method->hasReturnType() ? ': '.$method->getReturnType() : ''))
        ->values()->all();

    $classes = fn (string $directory, string $namespace) => collect(File::allFiles(__DIR__.'/../../src/'.$directory))
        ->map(fn (SplFileInfo $file) => $namespace.'\\'.str_replace('/', '\\', Str::beforeLast($file->getRelativePathname(), '.php')))
        ->sort()->values();

    $api = [
        'defaults' => require __DIR__.'/../../config/keyring.php',
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
