<?php

declare(strict_types=1);

namespace Keyring\Console;

use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Keyring\Contracts\SessionRegistry;
use Keyring\Facades\Keyring;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(name: 'keyring:prune')]
#[Signature('keyring:prune')]
#[Description('Forget old devices, email changes, security events and ended sessions')]
class PruneCommand extends Command
{
    public function handle(SessionRegistry $sessions): int
    {
        $this->call('model:prune', ['--model' => [Keyring::deviceModel(), Keyring::pendingChangeModel(), Keyring::securityEventModel()]]);

        $this->components->info("Pruned {$sessions->prune()} ended sessions.");

        return self::SUCCESS;
    }
}
