<script setup lang="ts">
import { computed, provide, ref, watch } from 'vue'

import { COLLAPSIBLE_INJECTION_KEY } from './context'

const props = withDefaults(
  defineProps<{
    defaultOpen?: boolean
    modelValue?: boolean
  }>(),
  {
    defaultOpen: false,
  },
)

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
}>()

const open = ref<boolean>(props.modelValue ?? props.defaultOpen)

watch(
  () => props.modelValue,
  value => {
    if (value === undefined) return
    open.value = value
  },
)

const toggle = () => {
  open.value = !open.value
  emit('update:modelValue', open.value)
}

provide(COLLAPSIBLE_INJECTION_KEY, { open, toggle })

const state = computed(() => (open.value ? 'open' : 'closed'))
</script>

<template>
  <div class="collapsible-root" :data-state="state">
    <slot />
  </div>
</template>
