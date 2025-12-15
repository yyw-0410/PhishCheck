<script setup lang="ts">
/**
 * FloatingActions - Wrapper that coordinates floating action buttons
 * Manages smooth push animation between chat button and scroll-to-top button
 * 
 * Usage:
 * <FloatingActions>
 *   <AIChatWidget />
 * </FloatingActions>
 */
import { ref, onMounted, onUnmounted, nextTick, provide, inject, readonly } from 'vue'
import { Button } from '@/components/ui/button'
import { ArrowUp } from 'lucide-vue-next'

// Scroll to top state
const showScrollTop = ref(false)
const SCROLL_THRESHOLD = 200
let scrollContainer: HTMLElement | null = null

// Track if chat is open (will be set by child via provide/inject or directly)
const isChatVisible = ref(false)

// Provide method for AIChatWidget to tell us when it's open
provide('setChatVisible', (visible: boolean) => {
    isChatVisible.value = visible
})

const handleScroll = () => {
    if (scrollContainer) {
        showScrollTop.value = scrollContainer.scrollTop > SCROLL_THRESHOLD
    }
}

const scrollToTop = () => {
    if (scrollContainer) {
        scrollContainer.scrollTo({ top: 0, behavior: 'smooth' })
    }
}

onMounted(async () => {
    await nextTick()
    // Use the ID we added to the main scroll container in App.vue
    scrollContainer = document.getElementById('main-scroll-container') as HTMLElement
    if (scrollContainer) {
        scrollContainer.addEventListener('scroll', handleScroll)
        handleScroll()
    } else {
        console.warn('FloatingActions: Could not find #main-scroll-container')
    }
})

onUnmounted(() => {
    if (scrollContainer) {
        scrollContainer.removeEventListener('scroll', handleScroll)
    }
})

// Show scroll button only when scrolled AND chat is not open
const showScrollButton = computed(() => showScrollTop.value && !isChatVisible.value)
</script>

<script lang="ts">
import { computed } from 'vue'
</script>

<template>
    <!-- Floating Buttons Container - reversed so scroll button is at bottom -->
    <div class="fixed bottom-8 right-8 z-50 flex flex-col-reverse items-center gap-2">
        <!-- Scroll to Top Button wrapper - maintains height during animation -->
        <div class="scroll-button-wrapper" :class="{ 'has-button': showScrollButton }">
            <Transition name="button-grow" appear>
                <Button v-if="showScrollButton" class="h-14 w-14 rounded-full shadow-lg bg-primary hover:bg-primary/90"
                    @click="scrollToTop" title="Scroll to top">
                    <ArrowUp class="h-6 w-6" />
                </Button>
            </Transition>
        </div>

        <!-- Chat Widget Wrapper -->
        <div>
            <slot />
        </div>
    </div>
</template>

<style scoped>
/* Scroll button wrapper - animates height to push/pull the chat button smoothly */
.scroll-button-wrapper {
    height: 0;
    overflow: visible;
    transition: height 0.4s ease-out;
    display: flex;
    align-items: flex-end;
    justify-content: center;
}

.scroll-button-wrapper.has-button {
    height: calc(3.5rem + 0.5rem);
    /* button height (14 = 3.5rem) + gap (2 = 0.5rem) */
}

/* Smooth button grow animation */
.button-grow-enter-active {
    transition: opacity 0.5s ease-out, transform 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
}

.button-grow-leave-active {
    transition: opacity 0.4s ease-out, transform 0.4s ease-out;
}

.button-grow-enter-from,
.button-grow-leave-to {
    opacity: 0;
    transform: scale(0);
}
</style>
