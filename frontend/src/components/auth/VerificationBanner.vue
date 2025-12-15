<script setup lang="ts">
import { computed } from "vue"
import { X, Mail } from "lucide-vue-next"
import { useAuthStore } from "@/stores/auth"
import { Button } from "@/components/ui/button"
import { API_BASE_URL } from "@/services/api"

const authStore = useAuthStore()

const showBanner = computed(() => {
    return authStore.isAuthenticated &&
        authStore.user &&
        authStore.user.is_verified === false &&
        !authStore.user.oauth_provider
})

const isResending = defineModel<boolean>('isResending', { default: false })
const resendSuccess = defineModel<boolean>('resendSuccess', { default: false })
const resendError = defineModel<string>('resendError', { default: '' })

async function resendVerification() {
    if (!authStore.user?.email || isResending.value) return

    isResending.value = true
    resendError.value = ''
    resendSuccess.value = false

    try {
        const response = await fetch(
            `${API_BASE_URL}/api/auth/resend-verification?email=${encodeURIComponent(authStore.user.email)}`,
            { method: 'POST', credentials: 'include' }
        )

        if (response.ok) {
            resendSuccess.value = true
        } else {
            const data = await response.json()
            resendError.value = data.detail || 'Failed to resend'
        }
    } catch {
        resendError.value = 'Network error'
    } finally {
        isResending.value = false
    }
}
</script>

<template>
    <div v-if="showBanner" class="bg-amber-500/10 border-b border-amber-500/20 px-4 py-3">
        <div class="flex items-center justify-between gap-4 max-w-screen-xl mx-auto">
            <div class="flex items-center gap-3 text-sm">
                <Mail class="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />
                <span class="text-amber-800 dark:text-amber-200">
                    <template v-if="resendSuccess">
                        ✓ Verification email sent! Check your inbox.
                    </template>
                    <template v-else-if="resendError">
                        {{ resendError }}
                    </template>
                    <template v-else>
                        Please verify your email to unlock all features.
                    </template>
                </span>
            </div>
            <Button v-if="!resendSuccess" variant="ghost" size="sm"
                class="text-amber-700 dark:text-amber-300 hover:bg-amber-500/20" :disabled="isResending"
                @click="resendVerification">
                {{ isResending ? 'Sending...' : 'Resend Email' }}
            </Button>
        </div>
    </div>
</template>
