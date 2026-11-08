<script setup lang="ts">
import { Head, useForm } from '@inertiajs/vue3'

const props = defineProps<{ action: 'confirm' | 'revert', url: string }>()
const form = useForm({})
</script>

<template>
  <Head :title="props.action === 'confirm' ? 'Confirm email change' : 'Secure your account'" />

  <main class="mx-auto mt-24 max-w-sm space-y-6 px-4">
    <template v-if="props.action === 'confirm'">
      <h1 class="text-xl font-semibold">Confirm your email change</h1>
      <p class="text-sm">Press the button to confirm this change to your account's email address.</p>
    </template>
    <template v-else>
      <h1 class="text-xl font-semibold">Wasn't you?</h1>
      <p class="text-sm">This puts your old email address back, removes sign-in methods added since the change, and signs out every device.</p>
    </template>

    <button type="button" :disabled="form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50" @click="form.post(props.url)">
      {{ props.action === 'confirm' ? 'Confirm change' : 'Undo the change and secure my account' }}
    </button>
  </main>
</template>
