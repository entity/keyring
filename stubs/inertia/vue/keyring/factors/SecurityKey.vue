<script setup lang="ts">
import type { Challenge } from '@entity/keyring/vue'
import { onMounted } from 'vue'

const { challenge } = defineProps<{ challenge: Challenge }>()

// Ask straight away; the button is there if the user dismissed the prompt.
onMounted(() => challenge.verifyKey())
</script>

<template>
  <div class="space-y-4 text-center">
    <p class="text-sm">
      {{ challenge.props.factor === 'passkey' ? 'Use your passkey to continue.' : `Insert and tap your security key (${challenge.props.authenticator.name}).` }}
    </p>
    <p v-if="challenge.form.errors.credential" role="alert" class="text-sm text-red-600">{{ challenge.form.errors.credential }}</p>
    <button type="button" :disabled="challenge.form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50" @click="challenge.verifyKey()">
      Try again
    </button>
  </div>
</template>
