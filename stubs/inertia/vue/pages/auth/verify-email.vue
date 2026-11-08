<script setup lang="ts">
import { Head, Link, useForm } from '@inertiajs/vue3'

defineProps<{ status?: string }>()

const form = useForm({})
</script>

<template>
  <Head title="Verify your email" />

  <main class="mx-auto mt-24 max-w-sm space-y-6 px-4">
    <h1 class="text-xl font-semibold">Check your email</h1>
    <p class="text-sm">We've sent you a link to verify your email address.</p>
    <p v-if="status === 'verification-link-sent'" class="text-sm text-green-700">A new link is on its way.</p>

    <button type="button" :disabled="form.processing" class="w-full rounded-md border px-3 py-2" @click="form.post('/email/verification-notification')">
      Send it again
    </button>

    <Link href="/logout" method="post" as="button" class="w-full text-sm text-gray-600 underline">Sign out</Link>
  </main>
</template>
