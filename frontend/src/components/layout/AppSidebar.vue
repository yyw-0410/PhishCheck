<script setup lang="ts">
import type { SidebarProps } from "@/components/ui/sidebar"
import { computed, onMounted } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useAPIStore } from '@/stores/api'

import {
  Mail,
  ShieldCheck,
  Activity,
  Shield,
  Globe,
  LifeBuoy,
  Send,
  Wifi,
  FileText,
  Lock,
} from "lucide-vue-next"

import NavMain from "@/components/layout/NavMain.vue"
import NavSecondary from "@/components/layout/NavSecondary.vue"
import NavUser from "@/components/layout/NavUser.vue"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar"

const props = withDefaults(defineProps<SidebarProps>(), {
  variant: "sidebar",
})

const authStore = useAuthStore()
const apiStore = useAPIStore()

// Check API status on mount
onMounted(() => {
  apiStore.checkAllAPIs()
})

// Computed status helpers
const getStatusBadge = (apiName: 'virustotal' | 'sublime' | 'urlscan' | 'ipqs' | 'hybridanalysis') => computed(() => {
  const status = apiStore.apiStatuses[apiName]?.status
  return status === 'live' ? 'Live' : status === 'offline' ? 'Offline' : 'Checking'
})

// User data reactive to auth state
const user = computed(() => {
  if (authStore.isAuthenticated && authStore.user) {
    return {
      name: authStore.user.name,
      email: authStore.user.email,
      avatar: authStore.user.avatar || "/avatars/user.jpg",
    }
  }
  return {
    name: "Guest User",
    email: "Sign in to access features",
    avatar: "/avatars/user.jpg",
  }
})

// Reactive Navigation Data
const navMain = computed(() => [
  // Email Live - In Development
  {
    title: "Email Live",
    url: "#",
    icon: Mail,
    badge: "Soon",
    items: [
      {
        title: "🚧 Coming Soon..",
        url: "#",
      },
    ],
  },
  // Analyzer - Always visible
  {
    title: "Analyzer",
    url: "#",
    icon: ShieldCheck,
    items: [
      {
        title: "EML Analysis",
        url: "/analyzer/eml",
      },
      {
        title: "Link Analysis",
        url: "/analyzer/link",
      },
      {
        title: "File Analysis",
        url: "/analyzer/file",
      },
    ],
  },
  // Integration - Real-time API Status
  {
    title: "Integration",
    url: "#",
    icon: Activity,
    items: [
      {
        title: "VirusTotal API",
        url: "#/integration/virustotal",
        icon: Shield,
        badge: getStatusBadge('virustotal').value
      },
      {
        title: "Sublime API",
        url: "#/integration/sublime",
        icon: Mail,
        badge: getStatusBadge('sublime').value
      },
      {
        title: "URLScan.io API",
        url: "#/integration/urlscan",
        icon: Globe,
        badge: getStatusBadge('urlscan').value
      },
      {
        title: "IPQS API",
        url: "#/integration/ipqs",
        icon: Wifi,
        badge: getStatusBadge('ipqs').value
      },
      {
        title: "Hybrid Analysis API",
        url: "#/integration/hybridanalysis",
        icon: Shield,
        badge: getStatusBadge('hybridanalysis').value
      },
    ],
  },
])

const navSecondary = [
  {
    title: "Terms of Service",
    url: "/terms",
    icon: FileText,
  },
  {
    title: "Privacy Policy",
    url: "/privacy",
    icon: Lock,
  },
  {
    title: "Support",
    url: "/support",
    icon: LifeBuoy,
  },
  {
    title: "Feedback",
    url: "/feedback",
    icon: Send,
  },
]
</script>

<template>
  <Sidebar v-bind="props">
    <SidebarHeader>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton size="lg" as-child>
            <a href="#" class="text-sidebar-foreground hover:text-sidebar-accent-foreground">
              <div
                class="flex aspect-square size-8 items-center justify-center rounded-lg bg-sidebar-primary text-sidebar-primary-foreground">
                <ShieldCheck class="size-4" />
              </div>
              <div class="grid flex-1 text-left text-sm leading-tight">
                <span class="truncate font-medium">PhishCheck</span>
                <span class="truncate text-xs">Security Platform</span>
              </div>
            </a>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarHeader>
    <SidebarContent class="flex flex-col">
      <!-- Main Sections -->
      <div class="flex-1 overflow-y-auto overflow-x-hidden">
        <NavMain :items="navMain" />
      </div>

      <!-- Support & Feedback at bottom - fixed position -->
      <div class="flex-shrink-0">
        <NavSecondary :items="navSecondary" />
      </div>
    </SidebarContent>
    <SidebarFooter>
      <NavUser :user="user" />
    </SidebarFooter>
    <SidebarRail />
  </Sidebar>
</template>
