<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import { Button } from '@/components/ui/button'
import { ArrowUp } from 'lucide-vue-next'

// Props
interface Props {
    threshold?: number
    smooth?: boolean
}

const props = withDefaults(defineProps<Props>(), {
    threshold: 200,
    smooth: true
})

const isVisible = ref(false)
let scrollContainer: HTMLElement | null = null

const handleScroll = () => {
    if (scrollContainer) {
        isVisible.value = scrollContainer.scrollTop > props.threshold
    }
}

const scrollToTop = () => {
    if (scrollContainer) {
        scrollContainer.scrollTo({
            top: 0,
            behavior: props.smooth ? 'smooth' : 'auto'
        })
    }
}

onMounted(async () => {
    // Wait for DOM to be ready
    await nextTick()

    // Find the main scrollable content area
    scrollContainer = document.querySelector('.flex-1.overflow-y-auto') as HTMLElement

    if (scrollContainer) {
        scrollContainer.addEventListener('scroll', handleScroll)
        handleScroll()
    }
})

onUnmounted(() => {
    if (scrollContainer) {
        scrollContainer.removeEventListener('scroll', handleScroll)
    }
})
</script>

<template>
    <Transition name="scroll-btn">
        <Button v-if="isVisible"
            class="fixed bottom-24 right-6 z-40 h-14 w-14 rounded-full shadow-lg bg-primary hover:bg-primary/90"
            @click="scrollToTop" title="Scroll to top">
            <ArrowUp class="h-6 w-6" />
        </Button>
    </Transition>
</template>

<style scoped>
.scroll-btn-enter-active,
.scroll-btn-leave-active {
    transition: all 0.3s ease;
}

.scroll-btn-enter-from,
.scroll-btn-leave-to {
    opacity: 0;
    transform: translateY(20px) scale(0.8);
}
</style>
