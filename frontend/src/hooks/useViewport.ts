import { computed, onMounted, onUnmounted, ref } from 'vue'

const getWindowWidth = () => (typeof window === 'undefined' ? 1024 : window.innerWidth)
const getWindowHeight = () => (typeof window === 'undefined' ? 768 : window.innerHeight)

export function useViewport() {
  const width = ref<number>(getWindowWidth())
  const height = ref<number>(getWindowHeight())

  const update = () => {
    width.value = getWindowWidth()
    height.value = getWindowHeight()
  }

  onMounted(() => {
    update()
    window.addEventListener('resize', update, { passive: true })
  })

  onUnmounted(() => {
    if (typeof window !== 'undefined') {
      window.removeEventListener('resize', update)
    }
  })

  const isMobile = computed(() => width.value < 640)
  const isTablet = computed(() => width.value >= 640 && width.value < 1024)
  const isDesktop = computed(() => width.value >= 1024)

  return {
    width,
    height,
    isMobile,
    isTablet,
    isDesktop,
  }
}
