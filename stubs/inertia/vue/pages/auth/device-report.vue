<script setup lang="ts">
import { Head, useForm } from '@inertiajs/vue3'

const props = defineProps<{ device: string, url: string }>()
const form = useForm({})
</script>

<template>
  <Head title="Secure your account" />

  <main class="mx-auto mt-24 max-w-sm space-y-6 px-4">
    <h1 class="text-xl font-semibold">Wasn't you?</h1>
    <p class="text-sm">This signs out {{ props.device }} and every "remember me" sign-in. Change your password afterwards if you think someone knows it.</p>

    <button type="button" :disabled="form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50" @click="form.post(props.url)">
      Sign that device out
    </button>
  </main>
</template>
