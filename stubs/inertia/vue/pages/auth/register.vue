<script setup lang="ts">
import { Head, Link, useForm } from '@inertiajs/vue3'

const form = useForm({ name: '', email: '', password: '', password_confirmation: '' })

function submit() {
  form.post('/register', { onFinish: () => form.reset('password', 'password_confirmation') })
}
</script>

<template>
  <Head title="Create an account" />

  <main class="mx-auto mt-24 max-w-sm space-y-6 px-4">
    <h1 class="text-xl font-semibold">Create an account</h1>

    <form class="space-y-4" @submit.prevent="submit">
      <label class="block">
        <span class="text-sm font-medium">Name</span>
        <input v-model="form.name" autocomplete="name" autofocus required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>
      <p v-if="form.errors.name" class="text-sm text-red-600">{{ form.errors.name }}</p>

      <label class="block">
        <span class="text-sm font-medium">Email</span>
        <input v-model="form.email" type="email" autocomplete="username" required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>
      <p v-if="form.errors.email" class="text-sm text-red-600">{{ form.errors.email }}</p>

      <label class="block">
        <span class="text-sm font-medium">Password</span>
        <span class="block text-xs text-gray-500">Long beats complicated. A few random words works well.</span>
        <input v-model="form.password" type="password" autocomplete="new-password" required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>
      <p v-if="form.errors.password" class="text-sm text-red-600">{{ form.errors.password }}</p>

      <label class="block">
        <span class="text-sm font-medium">Confirm password</span>
        <input v-model="form.password_confirmation" type="password" autocomplete="new-password" required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>

      <button type="submit" :disabled="form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Create account</button>
    </form>

    <p class="text-center text-sm">Already have an account? <Link href="/login" class="underline">Sign in</Link></p>
  </main>
</template>
