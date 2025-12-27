<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { Button } from "@/components/ui/button"
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card"
import {
    Field,
    FieldDescription,
    FieldGroup,
    FieldLabel,
    FieldSeparator,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { RouterLink } from 'vue-router'
import IconMicrosoft from "@/components/icons/IconMicrosoft.vue"
import IconGoogle from "@/components/icons/IconGoogle.vue"
import { useAuthStore } from '@/stores/auth'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000"
const router = useRouter()
const authStore = useAuthStore()

// Form data
const email = ref('')
const password = ref('')

// Handle email/password login
async function handleLogin() {
    const success = await authStore.login(email.value, password.value)
    if (success) {
        router.push('/')
    }
}

function handleMicrosoftLogin() {
    window.location.href = `${API_BASE_URL}/api/auth/microsoft/login`
}

function handleGoogleLogin() {
    window.location.href = `${API_BASE_URL}/api/auth/google/login`
}
</script>

<template>
    <div class="flex items-center justify-center py-12">
        <div class="w-full max-w-sm flex flex-col gap-6">
            <Card>
                <CardHeader class="text-center">
                    <CardTitle class="text-xl">
                        Welcome back
                    </CardTitle>
                    <CardDescription>
                        Login with your Microsoft Outlook or Google account
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <!-- Error message -->
                    <div v-if="authStore.error" class="mb-4 p-3 bg-destructive/10 text-destructive text-sm rounded-md">
                        {{ authStore.error }}
                    </div>
                    <form @submit.prevent="handleLogin">
                        <FieldGroup>
                            <Field>
                                <Button variant="outline" type="button" @click="handleMicrosoftLogin">
                                    <IconMicrosoft />
                                    Login with Microsoft Outlook
                                </Button>
                                <Button variant="outline" type="button" @click="handleGoogleLogin">
                                    <IconGoogle />
                                    Login with Google
                                </Button>
                            </Field>
                            <FieldSeparator class="*:data-[slot=field-separator-content]:bg-card">
                                Or continue with
                            </FieldSeparator>
                            <Field>
                                <FieldLabel for="email">
                                    Email
                                </FieldLabel>
                                <Input id="email" v-model="email" type="email" placeholder="m@example.com" required />
                            </Field>
                            <Field>
                                <div class="flex items-center">
                                    <FieldLabel for="password">
                                        Password
                                    </FieldLabel>
                                    <a href="#" class="ml-auto text-sm underline-offset-4 hover:underline">
                                        Forgot your password?
                                    </a>
                                </div>
                                <Input id="password" v-model="password" type="password" required />
                            </Field>
                            <Field>
                                <Button type="submit" :disabled="authStore.isLoading">
                                    {{ authStore.isLoading ? 'Logging in...' : 'Login' }}
                                </Button>
                                <FieldDescription class="text-center">
                                    Don't have an account?
                                    <RouterLink to="/signup" class="underline underline-offset-4 hover:text-primary">
                                        Sign up
                                    </RouterLink>
                                </FieldDescription>
                            </Field>
                        </FieldGroup>
                    </form>
                </CardContent>
            </Card>
            <FieldDescription class="px-6 text-center">
                By clicking continue, you agree to our
                <RouterLink to="/terms" class="underline underline-offset-4 hover:text-primary">Terms of Service
                </RouterLink>
                and
                <RouterLink to="/privacy" class="underline underline-offset-4 hover:text-primary">Privacy Policy
                </RouterLink>.
            </FieldDescription>
        </div>
    </div>
</template>
