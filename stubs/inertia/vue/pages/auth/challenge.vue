<script setup lang="ts">
import { useChallenge, type ChallengeProps } from '@entity/keyring/vue'
import { Head } from '@inertiajs/vue3'
import { computed, reactive, ref } from 'vue'
import factors from '../../keyring/factors'

const props = defineProps<ChallengeProps>()
const challenge = reactive(useChallenge(props, factors))
const showingAlternatives = ref(false)

// A factor with no component yet gets the closest built-in one.
const component = computed(() => challenge.component ?? (props.challenge.options ? factors['security-key'] : factors.totp))
</script>

<template>
  <Head :title="props.purpose === 'login' ? 'Verify it\'s you' : 'Confirm it\'s you'" />

  <main class="mx-auto mt-24 max-w-sm space-y-6 px-4">
    <h1 class="text-xl font-semibold">{{ props.purpose === 'login' ? 'One more step' : 'Confirm it\'s you' }}</h1>

    <component :is="component" :key="`${props.factor}:${props.authenticator.id}`" :challenge="challenge" :page="props" />

    <label v-if="props.canTrustDevice" class="flex items-center gap-2 text-sm">
      <input v-model="challenge.form.trust" type="checkbox">
      Don't ask again on this device
    </label>

    <div v-if="props.alternatives.length" class="border-t pt-4">
      <button type="button" class="text-sm text-gray-600 underline" @click="showingAlternatives = !showingAlternatives">
        Try another way
      </button>

      <ul v-if="showingAlternatives" class="mt-3 space-y-2">
        <li v-for="option in props.alternatives" :key="`${option.factor}:${option.id}`">
          <button type="button" class="w-full rounded-md border px-3 py-2 text-left text-sm hover:bg-gray-50" @click="challenge.switchTo(option)">
            {{ option.name }}
            <span v-if="option.hint" class="block text-xs text-gray-500">{{ option.hint }}</span>
          </button>
        </li>
      </ul>
    </div>
  </main>
</template>
