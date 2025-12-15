<script setup lang="ts">
import type { LucideIcon } from "lucide-vue-next"
import { ChevronRight, RefreshCw } from "lucide-vue-next"
import { RouterLink, useRoute } from "vue-router"
import { useSidebarStore } from "@/stores/sidebar"
import { useAPIStore } from "@/stores/api"
import { ref } from "vue"

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible"
import {
  SidebarGroup,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@/components/ui/sidebar"

const sidebarStore = useSidebarStore()
const apiStore = useAPIStore()
const route = useRoute()
const isRefreshing = ref(false)

defineProps<{
  items: {
    title: string
    url: string
    icon?: LucideIcon
    isActive?: boolean
    items?: {
      title: string
      url: string
      icon?: LucideIcon
      badge?: string
    }[]
  }[]
}>()

// Helper to check if URL is a valid route (starts with / and not #)
const isValidRoute = (url: string) => url.startsWith('/') && !url.startsWith('#')

// Check if item is active based on current route
const isItemActive = (url: string) => {
  if (!isValidRoute(url)) return false
  return route.path === url
}

// Check if this is an integration item
const isIntegrationItem = (url: string) => url.includes('#/integration/')

// Handle integration item click to refresh status
const handleIntegrationClick = async (e: Event) => {
  e.preventDefault()
  if (isRefreshing.value) return
  
  isRefreshing.value = true
  await apiStore.checkAllAPIs()
  isRefreshing.value = false
}
</script>

<template>
  <SidebarGroup>
    <SidebarMenu>
      <Collapsible 
        v-for="item in items" 
        :key="item.title" 
        as-child 
        :open="sidebarStore.isMenuOpen(item.title)"
        @update:open="(open: boolean) => sidebarStore.setMenuOpen(item.title, open)"
        class="group/collapsible w-full"
      >
        <SidebarMenuItem>
          <CollapsibleTrigger as-child>
            <SidebarMenuButton :tooltip="item.title">
              <component :is="item.icon" v-if="item.icon" />
              <span class="font-semibold">{{ item.title }}</span>
              <ChevronRight
                class="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90" />
            </SidebarMenuButton>
          </CollapsibleTrigger>
          <CollapsibleContent>
            <SidebarMenuSub>
              <SidebarMenuSubItem v-for="subItem in item.items" :key="subItem.title">
                <SidebarMenuSubButton as-child>
                  <!-- Valid route with active state -->
                  <RouterLink 
                    v-if="isValidRoute(subItem.url)" 
                    :to="subItem.url" 
                    class="flex items-center justify-between"
                    :class="{ 'bg-primary/10 text-primary font-medium': isItemActive(subItem.url) }"
                  >
                    <div class="flex items-center gap-2">
                      <component :is="subItem.icon" v-if="subItem.icon" class="h-4 w-4" :class="isItemActive(subItem.url) ? 'text-primary' : 'text-muted-foreground'" />
                      <span>{{ subItem.title }}</span>
                    </div>
                    <span v-if="subItem.badge"
                      class="rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide" :class="{
                        'bg-green-500/10 text-green-600 dark:text-green-400': subItem.badge === 'Live',
                        'bg-red-500/10 text-red-600 dark:text-red-400': subItem.badge === 'Offline',
                        'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400': subItem.badge === 'Checking',
                        'bg-primary/10 text-primary': !['Live', 'Offline', 'Checking'].includes(subItem.badge)
                      }">
                      {{ subItem.badge }}
                    </span>
                  </RouterLink>
                  <!-- Integration item - clickable to refresh -->
                  <a 
                    v-else-if="isIntegrationItem(subItem.url)" 
                    href="#" 
                    class="flex items-center justify-between cursor-pointer hover:bg-muted/50 transition-colors"
                    @click="handleIntegrationClick"
                  >
                    <div class="flex items-center gap-2">
                      <component :is="subItem.icon" v-if="subItem.icon" class="h-4 w-4 text-muted-foreground" />
                      <span>{{ subItem.title }}</span>
                    </div>
                    <div class="flex items-center gap-1">
                      <RefreshCw 
                        v-if="isRefreshing" 
                        class="h-3 w-3 animate-spin text-muted-foreground" 
                      />
                      <span v-if="subItem.badge"
                        class="rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide" :class="{
                          'bg-green-500/10 text-green-600 dark:text-green-400': subItem.badge === 'Live',
                          'bg-red-500/10 text-red-600 dark:text-red-400': subItem.badge === 'Offline',
                          'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400': subItem.badge === 'Checking',
                          'bg-primary/10 text-primary': !['Live', 'Offline', 'Checking'].includes(subItem.badge)
                        }">
                        {{ subItem.badge }}
                      </span>
                    </div>
                  </a>
                  <!-- Other non-route links -->
                  <a v-else :href="subItem.url" class="flex items-center justify-between">
                    <div class="flex items-center gap-2">
                      <component :is="subItem.icon" v-if="subItem.icon" class="h-4 w-4 text-muted-foreground" />
                      <span>{{ subItem.title }}</span>
                    </div>
                    <span v-if="subItem.badge"
                      class="rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide" :class="{
                        'bg-green-500/10 text-green-600 dark:text-green-400': subItem.badge === 'Live',
                        'bg-red-500/10 text-red-600 dark:text-red-400': subItem.badge === 'Offline',
                        'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400': subItem.badge === 'Checking',
                        'bg-primary/10 text-primary': !['Live', 'Offline', 'Checking'].includes(subItem.badge)
                      }">
                      {{ subItem.badge }}
                    </span>
                  </a>
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
            </SidebarMenuSub>
          </CollapsibleContent>
        </SidebarMenuItem>
      </Collapsible>
    </SidebarMenu>
  </SidebarGroup>
</template>
