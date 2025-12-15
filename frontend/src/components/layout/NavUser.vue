<script setup lang="ts">
import {
  BadgeCheck,
  Bell,
  ChevronsUpDown,
  CreditCard,
  LogOut,
  Sparkles,
} from "lucide-vue-next"

import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'

const props = defineProps<{
  user: {
    name: string
    email: string
    avatar: string
  }
}>()

const router = useRouter()
const authStore = useAuthStore()
const { isMobile } = useSidebar()

function handleLogout() {
  authStore.logout()
  router.push('/login')
}

function handleSignIn() {
  router.push('/login')
}

function handleSignUp() {
  router.push('/signup')
}

function navigateTo(path: string) {
  router.push(path)
}
</script>

<template>
  <SidebarMenu>
    <SidebarMenuItem>
      <!-- When Authenticated: Show User Dropdown -->
      <DropdownMenu v-if="authStore.isAuthenticated">
        <DropdownMenuTrigger as-child>
          <SidebarMenuButton size="lg"
            class="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground">
            <Avatar class="h-8 w-8 rounded-lg">
              <AvatarImage :src="user.avatar" :alt="user.name" />
              <AvatarFallback class="rounded-lg">
                CN
              </AvatarFallback>
            </Avatar>
            <div class="grid flex-1 text-left text-sm leading-tight">
              <span class="truncate font-medium">{{ user.name }}</span>
              <span class="truncate text-xs">{{ user.email }}</span>
            </div>
            <ChevronsUpDown class="ml-auto size-4" />
          </SidebarMenuButton>
        </DropdownMenuTrigger>
        <DropdownMenuContent class="w-[--reka-dropdown-menu-trigger-width] min-w-56 rounded-lg"
          :side="isMobile ? 'bottom' : 'right'" align="end" :side-offset="4">
          <DropdownMenuLabel class="p-0 font-normal">
            <div class="flex items-center gap-2 px-1 py-1.5 text-left text-sm">
              <Avatar class="h-8 w-8 rounded-lg">
                <AvatarImage :src="user.avatar" :alt="user.name" />
                <AvatarFallback class="rounded-lg">
                  CN
                </AvatarFallback>
              </Avatar>
              <div class="grid flex-1 text-left text-sm leading-tight">
                <span class="truncate font-semibold">{{ user.name }}</span>
                <span class="truncate text-xs">{{ user.email }}</span>
              </div>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuGroup>
            <DropdownMenuItem @click="navigateTo('/billing')">
              <Sparkles />
              Upgrade to Pro
            </DropdownMenuItem>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuGroup>
            <DropdownMenuItem @click="navigateTo('/account')">
              <BadgeCheck />
              Account
            </DropdownMenuItem>
            <DropdownMenuItem @click="navigateTo('/billing')">
              <CreditCard />
              Billing
            </DropdownMenuItem>
            <DropdownMenuItem @click="navigateTo('/notifications')">
              <Bell />
              Notifications
            </DropdownMenuItem>
          </DropdownMenuGroup>
          <DropdownMenuSeparator />
          <DropdownMenuItem @click="handleLogout">
            <LogOut />
            Log out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <!-- When NOT Authenticated: Show Sign In/Sign Up Buttons -->
      <div v-else class="flex flex-col gap-2 p-2">
        <Button size="sm" class="w-full" @click="handleSignIn">
          Sign In
        </Button>
        <Button size="sm" variant="outline" class="w-full" @click="handleSignUp">
          Sign Up
        </Button>
      </div>
    </SidebarMenuItem>
  </SidebarMenu>
</template>
