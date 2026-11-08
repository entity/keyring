<?php

namespace Keyring\Console;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\ServiceProvider;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'keyring:install')]
class InstallCommand extends Command
{
    protected $signature = 'keyring:install
        {--inertia= : Also publish Inertia pages for "vue" or "react"}
        {--force : Overwrite files that already exist}';

    protected $description = 'Install Keyring: config, migrations, a service provider and your registration action';

    public function handle(Filesystem $files): int
    {
        $this->callSilently('vendor:publish', ['--tag' => 'keyring-config', '--force' => $this->option('force')]);
        $this->callSilently('vendor:publish', ['--tag' => 'keyring-migrations', '--force' => $this->option('force')]);

        $this->copy($files, 'KeyringServiceProvider.php', app_path('Providers/KeyringServiceProvider.php'));
        $this->copy($files, 'CreateNewUser.php', app_path('Actions/Keyring/CreateNewUser.php'));

        ServiceProvider::addProviderToBootstrapFile('App\\Providers\\KeyringServiceProvider');

        if ($stack = $this->option('inertia')) {
            if (! in_array($stack, ['vue', 'react'], true)) {
                $this->components->error('The --inertia option must be "vue" or "react".');

                return self::FAILURE;
            }

            $files->copyDirectory(__DIR__."/../../stubs/inertia/{$stack}/pages", resource_path('js/pages'));
            $files->copyDirectory(__DIR__."/../../stubs/inertia/{$stack}/keyring", resource_path('js/keyring'));

            $this->components->info("Inertia {$stack} pages published to resources/js/pages/auth.");
        }

        $this->components->info('Keyring installed.');
        $this->components->bulletList([
            'Add <comment>use Keyring\Concerns\HasKeyring;</comment> to your User model',
            'Run <comment>php artisan migrate</comment>',
            'Already using Fortify? Run <comment>php artisan keyring:import fortify</comment>',
        ]);

        return self::SUCCESS;
    }

    protected function copy(Filesystem $files, string $stub, string $target): void
    {
        if ($files->exists($target) && ! $this->option('force')) {
            $this->components->warn("Skipped {$target}, it already exists.");

            return;
        }

        $files->ensureDirectoryExists(dirname($target));
        $files->copy(__DIR__.'/../../stubs/'.$stub, $target);
    }
}
