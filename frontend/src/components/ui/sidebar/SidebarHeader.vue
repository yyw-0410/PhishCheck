<script setup lang="ts">
import type { HTMLAttributes } from "vue"
import { cn } from "@/lib/utils"

const props = defineProps<{
  class?: HTMLAttributes["class"]
}>()
</script>

<template>
  <div data-sidebar="header" :class="cn('sticky top-0 z-10 flex w-full flex-col gap-2 bg-sidebar py-1.5', props.class)">
    <slot />
  </div>
</template>
