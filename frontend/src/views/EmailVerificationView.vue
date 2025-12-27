<script setup lang="ts">
import { computed, onMounted } from "vue"
import { useRoute, useRouter, RouterLink } from "vue-router"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"

const route = useRoute()
const router = useRouter()

// Redirect to home if no query params (user typed URL directly)
onMounted(() => {
    if (!route.query.success && !route.query.error && !route.query.token) {
        router.replace('/')
    }
})

const success = computed(() => route.query.success === "true")
const email = computed(() => route.query.email as string || "")
const error = computed(() => route.query.error as string || "")
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

                <!-- Success State -->
                <template v-if="success">
                    <div class="w-20 h-20 bg-green-500/10 rounded-full flex items-center justify-center mx-auto">
                        <svg class="w-10 h-10 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7">
                            </path>
                        </svg>
                    </div>
                    <h2 class="text-xl font-semibold text-green-500">Email Verified!</h2>
                    <p class="text-sm text-muted-foreground">
                        Your email <strong>{{ email }}</strong> has been successfully verified.
                    </p>
                    <p class="text-sm text-muted-foreground">
                        You now have access to all features.
                    </p>
                    <RouterLink to="/">
                        <Button class="w-full mt-4">Continue to App</Button>
                    </RouterLink>
                </template>

                <!-- Error State -->
                <template v-else>
                    <div class="w-20 h-20 bg-destructive/10 rounded-full flex items-center justify-center mx-auto">
                        <svg class="w-10 h-10 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                    </div>
                    <h2 class="text-xl font-semibold text-destructive">Verification Failed</h2>
                    <p class="text-sm text-muted-foreground">
                        <template v-if="error === 'invalid_token'">
                            This verification link is invalid or has expired.
                        </template>
                        <template v-else>
                            Something went wrong during verification.
                        </template>
                    </p>
                    <p class="text-xs text-muted-foreground">
                        Please try logging in and requesting a new verification email.
                    </p>
                    <RouterLink to="/login">
                        <Button variant="outline" class="w-full mt-4">Go to Login</Button>
                    </RouterLink>
                </template>
            </div>
        </div>
    </div>
</template>
