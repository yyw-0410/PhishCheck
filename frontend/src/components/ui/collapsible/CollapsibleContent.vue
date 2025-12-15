<script setup lang="ts">
import { computed, inject } from 'vue'

import { COLLAPSIBLE_INJECTION_KEY, type CollapsibleContext } from './context'

const context = inject<CollapsibleContext | null>(COLLAPSIBLE_INJECTION_KEY, null)

const state = computed(() => (context?.open.value ? 'open' : 'closed'))
</script>

<template>
  <div class="collapsible-content" :data-state="state" v-show="context?.open.value">
    <slot />
  </div>
</template>
