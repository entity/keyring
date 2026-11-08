<script setup lang="ts">
import type { Challenge } from '@entity/keyring/vue'
import { computed } from 'vue'

const { challenge } = defineProps<{ challenge: Challenge }>()

const copy = computed(() => {
  const { factor, authenticator } = challenge.props

  return {
    'totp': { label: 'Code from your authenticator app', hint: authenticator.name, inputmode: 'numeric', autocomplete: 'one-time-code' },
    'email-code': { label: 'Code from your email', hint: authenticator.hint, inputmode: 'numeric', autocomplete: 'one-time-code' },
    'recovery': { label: 'Recovery code', hint: `${authenticator.remaining ?? 0} left`, inputmode: 'text', autocomplete: 'off' },
  }[factor] ?? { label: 'Code', hint: null, inputmode: 'text', autocomplete: 'one-time-code' }
})

// Factors that send codes say whether one was sent.
const needsSending = computed(() => 'sent' in challenge.props.challenge)
</script>

<template>
  <div class="space-y-4">
    <div v-if="needsSending && !challenge.props.challenge.sent" class="space-y-2">
      <p class="text-sm">We'll email a code to {{ challenge.props.authenticator.hint }}.</p>
      <button type="button" class="w-full rounded-md bg-black px-3 py-2 text-white" @click="challenge.send()">Send code</button>
    </div>

    <form v-else class="space-y-4" @submit.prevent="challenge.submit()">
      <label class="block">
        <span class="text-sm font-medium">{{ copy.label }}</span>
        <span v-if="copy.hint" class="block text-xs text-gray-500">{{ copy.hint }}</span>
        <input
          v-model="challenge.form.code"
          :inputmode="copy.inputmode"
          :autocomplete="copy.autocomplete"
          :aria-invalid="!!challenge.form.errors.code"
          aria-describedby="code-error"
          autofocus
          required
          class="mt-1 w-full rounded-md border px-3 py-2 tracking-widest"
        >
      </label>
      <p v-if="challenge.form.errors.code" id="code-error" class="text-sm text-red-600">{{ challenge.form.errors.code }}</p>
      <button type="submit" :disabled="challenge.form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Verify</button>
      <button v-if="needsSending" type="button" class="w-full text-sm text-gray-600 underline" @click="challenge.send()">Send a new code</button>
    </form>
  </div>
</template>
