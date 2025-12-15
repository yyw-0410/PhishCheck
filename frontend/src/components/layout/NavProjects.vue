<script setup lang="ts">
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"

defineProps<{
  items: {
    title: string
    url: string
    badge?: string
  }[]
}>()
</script>

<template>
  <SidebarGroup class="group-data-[collapsible=icon]:hidden">
    <SidebarGroupLabel>Quick Actions</SidebarGroupLabel>
    <SidebarMenu>
      <SidebarMenuItem v-for="item in items" :key="item.title">
        <SidebarMenuButton as-child>
          <a :href="item.url" class="flex items-center justify-between">
            <span>{{ item.title }}</span>
            <span
              v-if="item.badge"
              class="rounded-md bg-green-500/10 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-green-600 dark:text-green-400"
            >
              {{ item.badge }}
            </span>
          </a>
        </SidebarMenuButton>
      </SidebarMenuItem>
    </SidebarMenu>
  </SidebarGroup>
</template>
