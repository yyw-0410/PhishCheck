<script setup lang="ts">
import { computed } from "vue"
import type { SidebarProps } from "."
import { cn } from "@/lib/utils"
import { Sheet, SheetContent } from '@/components/ui/sheet'
import { SIDEBAR_WIDTH_MOBILE, useSidebar } from "./utils"

defineOptions({
  inheritAttrs: false,
})

const props = withDefaults(defineProps<SidebarProps>(), {
  side: "left",
  variant: "sidebar",
  collapsible: "offcanvas",
})

const { isMobile, state, openMobile, setOpenMobile } = useSidebar()

const sidebarWidthClass = computed(() => {
  return state.value === 'collapsed' ? 'w-0' : 'w-60'
})
</script>

<template>
  <div v-if="collapsible === 'none'"
    :class="cn('flex h-full w-[--sidebar-width] flex-col bg-sidebar text-sidebar-foreground', props.class)"
    v-bind="$attrs">
    <slot />
  </div>

  <Sheet v-else-if="isMobile" :open="openMobile" v-bind="$attrs" @update:open="setOpenMobile">
    <SheetContent data-sidebar="sidebar" data-mobile="true" :side="side"
      class="bg-sidebar p-0 text-sidebar-foreground [&>button]:hidden" :style="{
        width: SIDEBAR_WIDTH_MOBILE,
        maxWidth: SIDEBAR_WIDTH_MOBILE,
      }">
      <div class="flex h-full w-full flex-col">
        <slot />
      </div>
    </SheetContent>
  </Sheet>

  <div v-else class="group peer hidden md:block shrink-0" :data-state="state"
    :data-collapsible="state === 'collapsed' ? collapsible : ''" :data-variant="variant" :data-side="side">
    <!-- This is what handles the sidebar gap on desktop  -->
    <div :class="cn(
      'duration-200 relative h-svh bg-transparent transition-[width] ease-linear',
      sidebarWidthClass,
      'group-data-[side=right]:rotate-180',
    )" />
    <div :class="cn(
      'duration-200 fixed inset-y-0 z-10 hidden h-svh w-60 transition-[left,right,width] ease-linear md:flex',
      side === 'left'
        ? 'left-0 group-data-[collapsible=offcanvas]:left-[calc(var(--sidebar-width)*-1)]'
        : 'right-0 group-data-[collapsible=offcanvas]:right-[calc(var(--sidebar-width)*-1)]',
      // Adjust the padding for floating and inset variants.
      variant === 'floating' || variant === 'inset'
        ? 'p-2 group-data-[collapsible=icon]:w-[calc(var(--sidebar-width-icon)_+_theme(spacing.4)_+_2px)]'
        : 'group-data-[collapsible=icon]:w-[--sidebar-width-icon] group-data-[side=left]:border-r group-data-[side=right]:border-l',
      props.class,
    )" v-bind="$attrs">
      <div data-sidebar="sidebar"
        class="flex h-full w-full flex-col bg-sidebar text-sidebar-foreground group-data-[variant=floating]:rounded-lg group-data-[variant=floating]:border group-data-[variant=floating]:border-sidebar-border group-data-[variant=floating]:shadow">
        <slot />
      </div>
    </div>
  </div>
</template>
