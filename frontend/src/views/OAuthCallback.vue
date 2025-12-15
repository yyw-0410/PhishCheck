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
    <div class="min-h-screen flex items-center justify-center bg-background p-6">
        <div class="max-w-md w-full space-y-6">
            <div class="text-center">
                <!-- Loading State -->
                <div v-if="status === 'loading'" class="space-y-4">
                    <div class="animate-spin rounded-full h-16 w-16 border-b-2 border-primary mx-auto"></div>
                    <h2 class="text-2xl font-semibold">Authenticating...</h2>
                    <p class="text-muted-foreground">Please wait while we complete your login</p>
                </div>

                <!-- Success State -->
                <div v-else-if="status === 'success'" class="space-y-4">
                    <div class="flex items-center justify-center">
                        <svg class="w-16 h-16 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7">
                            </path>
                        </svg>
                    </div>
                    <h2 class="text-2xl font-semibold text-green-600">Success!</h2>
                    <p class="text-muted-foreground">{{ message }}</p>
                </div>

                <!-- Error State -->
                <div v-else-if="status === 'error'" class="space-y-4">
                    <div class="flex items-center justify-center">
                        <svg class="w-16 h-16 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </div>
                    <h2 class="text-2xl font-semibold text-destructive">Error</h2>
                    <p class="text-muted-foreground">{{ message }}</p>
                    <p class="text-sm text-muted-foreground">Redirecting to login...</p>
                </div>
            </div>
        </div>
    </div>
</template>
