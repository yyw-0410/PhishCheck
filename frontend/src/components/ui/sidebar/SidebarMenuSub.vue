<script setup lang="ts">
import type { HTMLAttributes } from "vue"
import { cn } from "@/lib/utils"

const props = defineProps<{
  class?: HTMLAttributes["class"]
}>()
</script>

<template>
  <ul data-sidebar="menu-badge" :class="cn(
    'w-full flex min-w-0 translate-x-px flex-col gap-1 border-l border-sidebar-border py-0.5 ml-4 pr-4',
    'group-data-[collapsible=icon]:hidden',
    props.class,
  )">
    <slot />
  </ul>
</template>
