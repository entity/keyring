<?php

declare(strict_types=1);

use Rector\CodeQuality\Rector\FuncCall\SortCallLikeNamedArgsRector;
use Rector\CodeQuality\Rector\If_\ExplicitNullableObjectInstanceRector;
use Rector\CodingStyle\Rector\ArrowFunction\ArrowFunctionDelegatingCallToFirstClassCallableRector;
use Rector\Config\RectorConfig;
use Rector\Php55\Rector\String_\StringClassNameToClassConstantRector;
use Rector\TypeDeclaration\Rector\ArrowFunction\AddArrowFunctionReturnTypeRector;
use Rector\TypeDeclaration\Rector\Closure\AddClosureVoidReturnTypeWhereNoReturnRector;
use Rector\TypeDeclaration\Rector\Closure\ClosureReturnTypeRector;
use Rector\TypeDeclaration\Rector\FuncCall\AddArrayFunctionClosureParamTypeRector;
use RectorLaravel\Rector\Coalesce\ApplyDefaultInsteadOfNullCoalesceRector;
use RectorLaravel\Rector\FuncCall\AppToResolveRector;
use RectorLaravel\Rector\If_\ThrowIfRector;
use RectorLaravel\Rector\StaticCall\CarbonToDateFacadeRector;
use RectorLaravel\Rector\StaticCall\DispatchToHelperFunctionsRector;
use RectorLaravel\Set\LaravelSetList;

// No privatization set: Keyring's protected members are extension points.

return RectorConfig::configure()
    ->withPaths([
        __DIR__.'/config',
        __DIR__.'/database',
        __DIR__.'/routes',
        __DIR__.'/src',
        __DIR__.'/tests',
    ])
    ->withPhpSets()
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        typeDeclarations: true,
        instanceOf: true,
        earlyReturn: true,
    )
    ->withSets([
        LaravelSetList::LARAVEL_130,
        LaravelSetList::LARAVEL_CODE_QUALITY,
        LaravelSetList::LARAVEL_COLLECTION,
        LaravelSetList::LARAVEL_IF_HELPERS,
        LaravelSetList::LARAVEL_TYPE_DECLARATIONS,
    ])
    ->withSkip([
        // Laravel's own style: app() over resolve(), the Dispatchable trait
        // over event(), and untyped one-line closures. Every file declares
        // strict_types, which Pint adds.
        AppToResolveRector::class,
        DispatchToHelperFunctionsRector::class,
        AddArrowFunctionReturnTypeRector::class,
        AddClosureVoidReturnTypeWhereNoReturnRector::class,
        ClosureReturnTypeRector::class,
        AddArrayFunctionClosureParamTypeRector::class,
        // `$attempt === null` reads better than `! $attempt instanceof Attempt`.
        ExplicitNullableObjectInstanceRector::class,
        // now() and Carbon, as in Laravel's docs; named arguments in the order that reads best.
        CarbonToDateFacadeRector::class,
        SortCallLikeNamedArgsRector::class,
        // config('key') ?? $fallback also covers keys set to null; a default doesn't.
        ApplyDefaultInsteadOfNullCoalesceRector::class,
        // A plain if reads better than throw_unless(preg_match(...)).
        ThrowIfRector::class,
        // The provider it registers is the app's, which only exists once published.
        StringClassNameToClassConstantRector::class => [__DIR__.'/src/Console/InstallCommand.php'],
        // Pest datasets treat closures and first-class callables differently.
        ArrowFunctionDelegatingCallToFirstClassCallableRector::class => [__DIR__.'/tests'],
    ]);
