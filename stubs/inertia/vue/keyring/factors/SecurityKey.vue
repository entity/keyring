<script setup lang="ts">
import type { ChallengeProps } from '@entity/keyring'
import { onMounted } from 'vue'

const { challenge, page } = defineProps<{ challenge: any, page: ChallengeProps }>()

// Ask straight away; the button is there if the user dismissed the prompt.
onMounted(() => challenge.useKey())
</script>

<template>
  <div class="space-y-4 text-center">
    <p class="text-sm">
      {{ page.factor === 'passkey' ? 'Use your passkey to continue.' : `Insert and tap your security key (${page.authenticator.name}).` }}
    </p>
    <p v-if="challenge.form.errors.credential" class="text-sm text-red-600">{{ challenge.form.errors.credential }}</p>
    <button type="button" :disabled="challenge.form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50" @click="challenge.useKey()">
      Try again
    </button>
  </div>
</template>
