<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const status = ref<'loading' | 'success' | 'error'>('loading')
const message = ref('')

onMounted(async () => {
    try {
        // Get OAuth response from URL params - now includes session_token
        const sessionToken = route.query.session_token as string
        const accessToken = route.query.access_token as string
        const email = route.query.email as string
        const name = route.query.name as string
        const picture = route.query.picture as string

        if (!sessionToken || !email) {
            throw new Error('Missing authentication data')
        }

        // Determine provider from route path
        const provider = route.path.includes('microsoft') ? 'microsoft' : 'google'

        // Use the new handleOAuthCallback method
        authStore.handleOAuthCallback(sessionToken, {
            name: name || email,
            email,
            avatar: picture,
            oauth_provider: provider
        })

        status.value = 'success'
        message.value = 'Successfully authenticated! Redirecting...'

        // Redirect to EML analyzer after 2 seconds
        setTimeout(() => {
            router.push('/analyzer/eml')
        }, 2000)

    } catch (error) {
        status.value = 'error'
        message.value = error instanceof Error ? error.message : 'Authentication failed'

        // Redirect to login after 3 seconds
        setTimeout(() => {
            router.push('/login')
        }, 3000)
    }
})
</script>

<template>
    <!-- Dark backdrop - covers everything -->
    <div class="fixed inset-0 bg-background flex items-center justify-center p-6 z-[100]">
        <!-- Popup box -->
        <div
            class="bg-card border border-border rounded-2xl shadow-2xl max-w-sm w-full p-8 animate-in zoom-in-95 duration-300">
            <div class="text-center space-y-4">
                <!-- Logo -->
                <h1 class="text-xl font-bold text-primary mb-6">PhishCheck</h1>

                <!-- Loading State -->
                <div v-if="status === 'loading'" class="space-y-4">
                    <div
                        class="animate-spin rounded-full h-16 w-16 border-4 border-primary/30 border-t-primary mx-auto">
                    </div>
                    <h2 class="text-lg font-semibold">Authenticating...</h2>
                    <p class="text-sm text-muted-foreground">Please wait</p>
                </div>

                <!-- Success State -->
                <div v-else-if="status === 'success'" class="space-y-4">
                    <div class="w-20 h-20 bg-green-500/10 rounded-full flex items-center justify-center mx-auto">
                        <svg class="w-10 h-10 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7">
                            </path>
                        </svg>
                    </div>
                    <h2 class="text-xl font-semibold text-green-500">Authentication Successful!</h2>
                    <p class="text-sm text-muted-foreground">Redirecting you to the app...</p>
                    <div class="flex justify-center gap-1 pt-2">
                        <div class="w-2 h-2 bg-primary rounded-full animate-bounce" style="animation-delay: 0ms"></div>
                        <div class="w-2 h-2 bg-primary rounded-full animate-bounce" style="animation-delay: 150ms">
                        </div>
                        <div class="w-2 h-2 bg-primary rounded-full animate-bounce" style="animation-delay: 300ms">
                        </div>
                    </div>
                </div>

                <!-- Error State -->
                <div v-else-if="status === 'error'" class="space-y-4">
                    <div class="w-20 h-20 bg-destructive/10 rounded-full flex items-center justify-center mx-auto">
                        <svg class="w-10 h-10 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </div>
                    <h2 class="text-xl font-semibold text-destructive">Error</h2>
                    <p class="text-sm text-muted-foreground">{{ message }}</p>
                    <p class="text-xs text-muted-foreground">Redirecting to login...</p>
                </div>
            </div>
        </div>
    </div>
</template>
