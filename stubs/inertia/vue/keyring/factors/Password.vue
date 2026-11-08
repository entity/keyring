<script setup lang="ts">
import type { ChallengeProps } from '@entity/keyring'

const { challenge } = defineProps<{ challenge: any, page: ChallengeProps }>()
</script>

<template>
  <form class="space-y-4" @submit.prevent="challenge.submit()">
    <label class="block">
      <span class="text-sm font-medium">Password</span>
      <input v-model="challenge.form.password" type="password" autocomplete="current-password" autofocus required class="mt-1 w-full rounded-md border px-3 py-2">
    </label>
    <p v-if="challenge.form.errors.password" class="text-sm text-red-600">{{ challenge.form.errors.password }}</p>
    <button type="submit" :disabled="challenge.form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Continue</button>
  </form>
</template>
