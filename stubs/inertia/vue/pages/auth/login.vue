<script setup lang="ts">
import { usePasskeyLogin } from '@entity/keyring/vue'
import { Head, Link, useForm } from '@inertiajs/vue3'

defineProps<{ canResetPassword: boolean, status?: string }>()

const form = useForm({ email: '', password: '', remember: false })
const { supported, processing, error: passkeyError, signIn } = usePasskeyLogin({ autofill: true, remember: () => form.remember })

function submit() {
  form.post('/login', { onFinish: () => form.reset('password') })
}
</script>

<template>
  <Head title="Sign in" />

  <main class="mx-auto mt-24 max-w-sm space-y-6 px-4">
    <h1 class="text-xl font-semibold">Sign in</h1>
    <p v-if="status" class="text-sm text-green-700">{{ status }}</p>

    <form class="space-y-4" @submit.prevent="submit">
      <label class="block">
        <span class="text-sm font-medium">Email</span>
        <input v-model="form.email" type="email" autocomplete="username webauthn" autofocus required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>
      <p v-if="form.errors.email" class="text-sm text-red-600">{{ form.errors.email }}</p>

      <label class="block">
        <span class="flex justify-between text-sm font-medium">
          Password
          <Link v-if="canResetPassword" href="/forgot-password" class="font-normal text-gray-600 underline">Forgot it?</Link>
        </span>
        <input v-model="form.password" type="password" autocomplete="current-password" required class="mt-1 w-full rounded-md border px-3 py-2">
      </label>

      <label class="flex items-center gap-2 text-sm">
        <input v-model="form.remember" type="checkbox">
        Remember me
      </label>

      <button type="submit" :disabled="form.processing" class="w-full rounded-md bg-black px-3 py-2 text-white disabled:opacity-50">Sign in</button>
    </form>

    <div v-if="supported" class="space-y-2 border-t pt-4">
      <button type="button" :disabled="processing" class="w-full rounded-md border px-3 py-2" @click="signIn()">
        Sign in with a passkey
      </button>
      <p v-if="passkeyError" class="text-sm text-red-600">{{ passkeyError }}</p>
    </div>

    <p class="text-center text-sm">New here? <Link href="/register" class="underline">Create an account</Link></p>
  </main>
</template>
