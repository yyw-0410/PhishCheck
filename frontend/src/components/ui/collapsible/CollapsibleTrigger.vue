<script setup lang="ts">
import { inject } from 'vue'

import { COLLAPSIBLE_INJECTION_KEY, type CollapsibleContext } from './context'

const context = inject<CollapsibleContext | null>(COLLAPSIBLE_INJECTION_KEY, null)

const onClick = () => {
  context?.toggle()
}
</script>

<template>
  <button
    type="button"
    class="collapsible-trigger"
    :data-state="context?.open.value ? 'open' : 'closed'"
    @click="onClick"
  >
    <slot />
  </button>
</template>

<style scoped>
.collapsible-trigger {
  width: 100%;
  text-align: left;
  background: none;
  border: none;
  padding: 0;
  color: inherit;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
}
</style>
