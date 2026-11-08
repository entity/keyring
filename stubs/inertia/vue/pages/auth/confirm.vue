<script setup lang="ts">
import type { ChallengeProps } from '@entity/keyring'
import Challenge from './challenge.vue'

const props = defineProps<ChallengeProps>()
</script>

<template>
  <Challenge v-bind="props" />
</template>
