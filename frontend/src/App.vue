<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterView, useRoute } from 'vue-router'
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar'
import AppSidebar from '@/components/layout/AppSidebar.vue'
import TopBar from '@/components/layout/TopBar.vue'
import FloatingActions from '@/components/layout/FloatingActions.vue'
import AIChatWidget from '@/components/chat/AIChatWidget.vue'
import VerificationBanner from '@/components/auth/VerificationBanner.vue'
import { useAuthStore } from '@/stores/auth'

const route = useRoute()
const authStore = useAuthStore()
const theme = ref(localStorage.getItem('theme') || 'dark')

const isDark = computed(() => theme.value === 'dark')
const isFullLayout = computed(() => route.meta.layout === 'full')
// Only center the layout for login/signup pages
const isCenteredLayout = computed(() => ['login', 'signup'].includes(route.name as string))

function toggleTheme() {
  theme.value = theme.value === 'dark' ? 'light' : 'dark'
  localStorage.setItem('theme', theme.value)
  updateTheme()
}

function updateTheme() {
  document.documentElement.setAttribute('data-theme', theme.value)
  if (theme.value === 'dark') {
    document.documentElement.classList.add('dark')
  } else {
    document.documentElement.classList.remove('dark')
  }
}

onMounted(() => {
  updateTheme()
  // Validate session on app start - clears stale localStorage if session is invalid
  if (authStore.isAuthenticated) {
    authStore.validateSession()
  }
})

// AI Chat expanded state - to push content when expanded
const isChatExpanded = ref(false)
const chatWidth = ref(0)

const onChatExpand = (expanded: boolean, width: number) => {
  isChatExpanded.value = expanded
  chatWidth.value = expanded ? width : 0
}

// Computed style for dynamic margin
const contentStyle = computed(() => {
  if (isChatExpanded.value && chatWidth.value > 0) {
    return { marginRight: `${chatWidth.value}px` }
  }
  return {}
})
</script>

<template>
  <!-- Full Page Layout (Login/Signup/Terms/Privacy/Support/Feedback) - No Sidebar/Header -->
  <div v-if="isFullLayout" class="auth-layout" :class="{ centered: isCenteredLayout }">
    <RouterView v-slot="{ Component }">
      <component :is="Component" :theme="theme" />
    </RouterView>
  </div>

  <!-- Main App Layout - With Sidebar/Header -->
  <SidebarProvider v-else>
    <AppSidebar />
    <SidebarInset class="h-svh overflow-hidden" :style="contentStyle">
      <VerificationBanner />
      <TopBar :is-dark="isDark" @toggle-theme="toggleTheme" />

      <div id="main-scroll-container" class="flex-1 overflow-y-auto overflow-x-hidden flex flex-col">
        <main class="main-content">
          <RouterView v-slot="{ Component }">
            <component :is="Component" :theme="theme" />
          </RouterView>
        </main>

        <footer class="app-footer">&copy; 2025 PhishCheck. All rights reserved.</footer>
      </div>
    </SidebarInset>

    <!-- Floating Actions Wrapper (coordinates chat + scroll buttons) -->
    <FloatingActions>
      <!-- AIChatWidget passed as slot for coordinated animation -->
      <AIChatWidget @expand="onChatExpand" />
    </FloatingActions>
  </SidebarProvider>
</template>

<style scoped>
/* Chat expanded state - push content on desktop (handled dynamically via inline style) */

:global(:root) {
  --main-bg: linear-gradient(180deg, rgba(255, 255, 255, 0.9) 0%, rgba(226, 232, 240, 0.4) 100%);
  /* Match dark background to the card color for a seamless edge */
  --main-bg-dark: var(--card);
}

/* Global layout reset to eliminate right-side gaps */
:global(html, body, #app) {
  margin: 0;
  padding: 0;
  width: 100%;
  max-width: 100%;
  overflow-x: hidden;
  height: 100%;
}

:global(*),
:global(*::before),
:global(*::after) {
  box-sizing: border-box;
}

:global(body) {
  background-color: var(--background);
}

:global(:root[data-theme='dark']) {
  --main-bg: var(--main-bg-dark);
}

.auth-layout {
  min-height: 100vh;
  width: 100%;
  background: var(--background);
}

/* Centered layout for login/signup */
.auth-layout.centered {
  display: flex;
  align-items: center;
  justify-content: center;
}

.main-content {
  padding: 0;
  background: var(--main-bg);
  flex: 1;
  position: relative;
  isolation: isolate;
}

:global([data-theme='dark']) .main-content {
  background: var(--main-bg-dark);
}

.app-footer {
  padding: 1rem 0 1.5rem;
  text-align: center;
  color: var(--color-text-soft);
  border-top: 1px solid rgba(148, 163, 184, 0.18);
  background: rgba(15, 23, 42, 0.1);
}

:global([data-theme='dark']) .app-footer {
  background: rgba(15, 23, 42, 0.78);
  border-top-color: rgba(71, 85, 105, 0.35);
}

:global([data-theme='dark']) body,
:global([data-theme='dark']) #app {
  background: var(--card);
  color: #e2e8f0;
}
</style>
