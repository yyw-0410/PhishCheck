import { ref } from 'vue'
import { defineStore } from 'pinia'

export const useSidebarStore = defineStore('sidebar', () => {
  // Track which menu sections are open (by title)
  const openMenus = ref<Set<string>>(new Set(['Analyzer']))

  function toggleMenu(title: string) {
    if (openMenus.value.has(title)) {
      openMenus.value.delete(title)
    } else {
      openMenus.value.add(title)
    }
  }

  function isMenuOpen(title: string): boolean {
    return openMenus.value.has(title)
  }

  function setMenuOpen(title: string, open: boolean) {
    if (open) {
      openMenus.value.add(title)
    } else {
      openMenus.value.delete(title)
    }
  }

  return { openMenus, toggleMenu, isMenuOpen, setMenuOpen }
})
