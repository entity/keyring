<script setup lang="ts">
import { Head, Link, useForm } from '@inertiajs/vue3'

defineProps<{ status?: string }>()

const form = useForm({ email: '' })
</script>

<template>
  <Head title="Forgot password" />

  <main class="mx-auto mt-24 max-w-sm space-y-6 px-4">
    <h1 class="text-xl font-semibold">Forgot your password?</h1>
    <p v-if="status" class="text-sm text-green-700">{{ status }}</p>

    <form class="space-y-4" @submit.prevent="form.post('/forgot-password')">
      <label class="block">
        <span class="text-sm font-medium">Email</span>
        <input v-model="form.email" type="email" autocomplete="username" autofocus required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>
      <p v-if="form.errors.email" class="text-sm text-red-600">{{ form.errors.email }}</p>

      <button type="submit" :disabled="form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Email me a reset link</button>
    </form>

    <p class="text-center text-sm"><Link href="/login" class="underline">Back to sign in</Link></p>
  </main>
</template>
