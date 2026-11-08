<script setup lang="ts">
import { Head, useForm } from '@inertiajs/vue3'

const props = defineProps<{ token: string, email: string }>()

const form = useForm({ token: props.token, email: props.email, password: '', password_confirmation: '' })
</script>

<template>
  <Head title="Reset password" />

  <main class="mx-auto mt-24 max-w-sm space-y-6 px-4">
    <h1 class="text-xl font-semibold">Choose a new password</h1>

    <form class="space-y-4" @submit.prevent="form.post('/reset-password', { onFinish: () => form.reset('password', 'password_confirmation') })">
      <label class="block">
        <span class="text-sm font-medium">Email</span>
        <input v-model="form.email" type="email" autocomplete="username" required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>
      <p v-if="form.errors.email" class="text-sm text-red-600">{{ form.errors.email }}</p>

      <label class="block">
        <span class="text-sm font-medium">New password</span>
        <input v-model="form.password" type="password" autocomplete="new-password" autofocus required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>
      <p v-if="form.errors.password" class="text-sm text-red-600">{{ form.errors.password }}</p>

      <label class="block">
        <span class="text-sm font-medium">Confirm new password</span>
        <input v-model="form.password_confirmation" type="password" autocomplete="new-password" required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>

      <button type="submit" :disabled="form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Reset password</button>
    </form>
  </main>
</template>
