<?php

namespace Keyring\Console;

use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Keyring\Contracts\SessionRegistry;
use Keyring\Facades\Keyring;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;

#[Signature('keyring:prune')]
#[Description('Forget old devices, email changes, security events and ended sessions')]
class PruneCommand extends Command
{
    public function handle(SessionRegistry $sessions): int
    {
        $this->call('model:prune', ['--model' => [Keyring::deviceModel(), PendingChange::class, SecurityEvent::class]]);

        $this->components->info("Pruned {$sessions->prune()} ended sessions.");

        return self::SUCCESS;
    }
}
