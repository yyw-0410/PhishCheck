<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { SidebarTrigger } from '@/components/ui/sidebar'

const props = defineProps<{
  isDark: boolean
}>()

const emit = defineEmits<{
  (e: 'toggle-theme'): void
}>()

const route = useRoute()

const pageInfo = computed(() => {
  const routeName = route.name as string
  const pageInfoMap: Record<string, { title: string; description: string }> = {
    'home': {
      title: 'EML Analysis',
      description: 'Upload a suspicious email to inspect with Sublime, VirusTotal, urlscan.io, IPQS, and Hybrid Analysis.'
    },
    'eml-analysis': {
      title: 'EML Analysis',
      description: 'Upload a suspicious email to inspect with Sublime, VirusTotal, urlscan.io, IPQS, and Hybrid Analysis.'
    },
    'link-analysis': {
      title: 'Link Analysis',
      description: 'Inspect suspicious URLs with VirusTotal, urlscan.io, and Sublime Security.'
    },
    'file-analysis': {
      title: 'File Analysis',
      description: 'Upload a file or enter a hash to check for threats using VirusTotal and Hybrid Analysis.'
    }
  }
  return pageInfoMap[routeName] || {
    title: 'PhishCheck',
    description: 'Security analysis tools for phishing detection.'
  }
})

const themeLabel = computed(() => (props.isDark ? 'Dark' : 'Light'))
const themeIcon = computed(() => (props.isDark ? '🌙' : '☀️'))
</script>

<template>
  <header class="topbar">
    <div class="flex items-center gap-4 min-w-0 flex-1 pl-2 md:pl-4">
      <SidebarTrigger class="hover:bg-sidebar-accent/50 rounded-md p-2 transition-colors shrink-0" />
      <div class="page-title min-w-0">
        <h2>{{ pageInfo.title }}</h2>
        <p class="hidden lg:block">{{ pageInfo.description }}</p>
      </div>
    </div>
    <button class="theme-switch shrink-0 mr-2 md:mr-4" type="button" @click="emit('toggle-theme')">
      <span class="switch-label">{{ themeLabel }} mode</span>
      <span class="switch-track" :class="{ active: isDark }">
        <span class="switch-thumb">
          <span class="switch-icon">{{ themeIcon }}</span>
        </span>
      </span>
    </button>
  </header>
</template>

<style scoped>
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem 1rem 0.75rem;
  border-bottom: 1px solid rgba(148, 163, 184, 0.18);
  gap: 1rem;
  z-index: 40;
  background: var(--background);
}

:global([data-theme='dark']) .topbar {
  background: rgba(15, 23, 42, 0.98);
  color: white;
}

:global([data-theme='light']) .topbar {
  background: rgba(255, 255, 255, 0.98);
  color: #1e293b;
}

@media (min-width: 768px) {
  .topbar {
    padding: 1.5rem 1rem 1rem;
  }
}

.page-title h2 {
  margin: 0;
  font-size: 1.25rem;
  line-height: 1.75rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: inherit;
}

@media (min-width: 768px) {
  .page-title h2 {
    font-size: 1.5rem;
  }
}

.page-title p {
  margin: 0.25rem 0 0;
  font-size: 0.875rem;
  opacity: 0.7;
}

.theme-switch {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  border: 1px solid rgba(148, 163, 184, 0.28);
  padding: 0.35rem 0.5rem;
  border-radius: 999px;
  background: transparent;
  cursor: pointer;
  color: inherit;
}

@media (min-width: 768px) {
  .theme-switch {
    gap: 0.75rem;
  }
}

.switch-label {
  font-size: 0.875rem;
  font-weight: 600;
  display: none;
}

@media (min-width: 1024px) {
  .switch-label {
    display: inline;
  }
}

.switch-track {
  width: 58px;
  height: 28px;
  border-radius: 999px;
  background: rgba(148, 163, 184, 0.35);
  position: relative;
  display: inline-flex;
  align-items: center;
  padding: 0 4px;
  transition: background 0.2s ease;
}

.switch-track.active {
  background: linear-gradient(135deg, #4f46e5, #2563eb);
}

.switch-thumb {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: white;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transform: translateX(0);
  transition: transform 0.2s ease, background 0.2s ease;
}

.switch-track.active .switch-thumb {
  transform: translateX(30px);
  background: #111827;
  color: white;
}
</style>
