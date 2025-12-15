<script setup lang="ts">
import type { LucideIcon } from "lucide-vue-next"
import { RouterLink } from 'vue-router'
import {
  SidebarGroup,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

defineProps<{
  items: {
    title: string
    url: string
    icon?: LucideIcon
    status?: string
  }[]
}>()
</script>

<template>
  <SidebarGroup>
    <SidebarMenu>
      <SidebarMenuItem v-for="item in items" :key="item.title">
        <SidebarMenuButton as-child size="sm">
          <RouterLink :to="item.url" class="flex items-center justify-between">
            <div class="flex items-center gap-2">
              <component :is="item.icon" v-if="item.icon" class="h-4 w-4 text-muted-foreground" />
              <span>{{ item.title }}</span>
            </div>
            <span v-if="item.status" class="text-[10px] font-medium uppercase tracking-wide" :class="{
              'text-green-600 dark:text-green-400': item.status === 'Live',
              'text-red-600 dark:text-red-400': item.status === 'Offline',
              'text-blue-600 dark:text-blue-400': item.status === 'Beta',
              'text-muted-foreground': item.status === 'Coming soon'
            }">
              {{ item.status }}
            </span>
          </RouterLink>
        </SidebarMenuButton>
      </SidebarMenuItem>
    </SidebarMenu>
  </SidebarGroup>
</template>
