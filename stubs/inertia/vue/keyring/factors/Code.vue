<script setup lang="ts">
import type { ChallengeProps } from '@entity/keyring'
import { computed } from 'vue'

const { challenge, page } = defineProps<{ challenge: any, page: ChallengeProps }>()

const copies: Record<string, { label: string, hint?: string | null, inputmode: 'numeric' | 'text' }> = {
  'totp': { label: 'Code from your authenticator app', hint: page.authenticator.name, inputmode: 'numeric' },
  'email-code': { label: 'Code from your email', hint: page.authenticator.hint, inputmode: 'numeric' },
  'recovery': { label: 'Recovery code', hint: `${page.authenticator.remaining ?? 0} left`, inputmode: 'text' },
}

const copy = computed(() => copies[page.factor] ?? { label: 'Code', hint: null, inputmode: 'text' })

// Factors that send codes say whether one was sent.
const needsSending = computed(() => 'sent' in page.challenge)
</script>

<template>
  <div class="space-y-4">
    <div v-if="needsSending && !page.challenge.sent" class="space-y-2">
      <p class="text-sm">We'll email a code to {{ page.authenticator.hint }}.</p>
      <button type="button" class="w-full rounded-md bg-black px-3 py-2 text-white" @click="challenge.send()">Send code</button>
    </div>

    <form v-else class="space-y-4" @submit.prevent="challenge.submit()">
      <label class="block">
        <span class="text-sm font-medium">{{ copy.label }}</span>
        <span v-if="copy.hint" class="block text-xs text-gray-500">{{ copy.hint }}</span>
        <input v-model="challenge.form.code" :inputmode="copy.inputmode" autocomplete="one-time-code" autofocus required class="mt-1 w-full rounded-md border px-3 py-2 tracking-widest">
      </label>
      <p v-if="challenge.form.errors.code" class="text-sm text-red-600">{{ challenge.form.errors.code }}</p>
      <button type="submit" :disabled="challenge.form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Verify</button>
      <button v-if="needsSending" type="button" class="w-full text-sm text-gray-600 underline" @click="challenge.send()">Send a new code</button>
    </form>
  </div>
</template>
