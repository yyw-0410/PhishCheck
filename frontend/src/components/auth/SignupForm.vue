<script setup lang="ts">
import { ref, computed, type HTMLAttributes } from "vue"
import { cn } from "@/lib/utils"
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
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { RouterLink, useRouter } from 'vue-router'
import { useAuthStore } from "@/stores/auth"

const props = defineProps<{
    class?: HTMLAttributes["class"]
}>()

const router = useRouter()
const authStore = useAuthStore()

const name = ref('')
const email = ref('')
const password = ref('')
const confirmPassword = ref('')
const validationError = ref('')

// Real-time password validation
const hasMinLength = computed(() => password.value.length >= 8)
const hasUppercase = computed(() => /[A-Z]/.test(password.value))
const hasLowercase = computed(() => /[a-z]/.test(password.value))
const hasNumber = computed(() => /\d/.test(password.value))
const passwordsMatch = computed(() => password.value === confirmPassword.value && confirmPassword.value !== '')

async function handleSubmit() {
    validationError.value = ''

    // Password validation
    if (password.value.length < 8) {
        validationError.value = 'Password must be at least 8 characters long'
        return
    }

    if (!/[A-Z]/.test(password.value)) {
        validationError.value = 'Password must contain at least one uppercase letter'
        return
    }

    if (!/[a-z]/.test(password.value)) {
        validationError.value = 'Password must contain at least one lowercase letter'
        return
    }

    if (!/\d/.test(password.value)) {
        validationError.value = 'Password must contain at least one digit'
        return
    }

    if (password.value !== confirmPassword.value) {
        validationError.value = 'Passwords do not match'
        return
    }

    const success = await authStore.register(name.value, email.value, password.value)

    if (success) {
        router.push('/')
    }
    // Error will be shown from authStore.error
}
</script>

<template>
    <div :class="cn('flex flex-col gap-6', props.class)">
        <Card>
            <CardHeader class="text-center">
                <CardTitle class="text-xl">
                    Create your account
                </CardTitle>
                <CardDescription>
                    Enter your email below to create your account
                </CardDescription>
            </CardHeader>
            <CardContent>
                <form @submit.prevent="handleSubmit">
                    <FieldGroup>
                        <!-- Error Message -->
                        <div v-if="authStore.error || validationError"
                            class="rounded-md bg-destructive/15 p-3 text-sm text-destructive">
                            {{ validationError || authStore.error }}
                        </div>
                        <Field>
                            <FieldLabel for="name">
                                Full Name
                            </FieldLabel>
                            <Input id="name" v-model="name" type="text" placeholder="John Doe" required />
                        </Field>
                        <Field>
                            <FieldLabel for="email">
                                Email
                            </FieldLabel>
                            <Input id="email" v-model="email" type="email" placeholder="m@example.com" required />
                        </Field>
                        <Field>
                            <Field class="grid grid-cols-2 gap-4">
                                <Field>
                                    <FieldLabel for="password">
                                        Password
                                    </FieldLabel>
                                    <Input id="password" v-model="password" type="password" required />
                                </Field>
                                <Field>
                                    <FieldLabel for="confirm-password">
                                        Confirm Password
                                    </FieldLabel>
                                    <Input id="confirm-password" v-model="confirmPassword" type="password" required />
                                </Field>
                            </Field>
                            <!-- Real-time password checklist -->
                            <div class="grid gap-1.5 mt-3 text-sm">
                                <div class="flex items-center gap-2"
                                    :class="hasMinLength ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'">
                                    <span class="w-4 h-4 flex items-center justify-center rounded-full text-xs"
                                        :class="hasMinLength ? 'bg-emerald-100 dark:bg-emerald-900' : 'bg-muted'">{{
                                        hasMinLength ? '✓' : '' }}</span>
                                    At least 8 characters
                                </div>
                                <div class="flex items-center gap-2"
                                    :class="hasUppercase ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'">
                                    <span class="w-4 h-4 flex items-center justify-center rounded-full text-xs"
                                        :class="hasUppercase ? 'bg-emerald-100 dark:bg-emerald-900' : 'bg-muted'">{{
                                        hasUppercase ? '✓' : '' }}</span>
                                    One uppercase letter
                                </div>
                                <div class="flex items-center gap-2"
                                    :class="hasLowercase ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'">
                                    <span class="w-4 h-4 flex items-center justify-center rounded-full text-xs"
                                        :class="hasLowercase ? 'bg-emerald-100 dark:bg-emerald-900' : 'bg-muted'">{{
                                        hasLowercase ? '✓' : '' }}</span>
                                    One lowercase letter
                                </div>
                                <div class="flex items-center gap-2"
                                    :class="hasNumber ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'">
                                    <span class="w-4 h-4 flex items-center justify-center rounded-full text-xs"
                                        :class="hasNumber ? 'bg-emerald-100 dark:bg-emerald-900' : 'bg-muted'">{{
                                        hasNumber ? '✓' : '' }}</span>
                                    One number
                                </div>
                                <div v-if="confirmPassword" class="flex items-center gap-2"
                                    :class="passwordsMatch ? 'text-emerald-600 dark:text-emerald-400' : 'text-destructive'">
                                    <span class="w-4 h-4 flex items-center justify-center rounded-full text-xs"
                                        :class="passwordsMatch ? 'bg-emerald-100 dark:bg-emerald-900' : 'bg-destructive/20'">{{
                                        passwordsMatch ? '✓' : '✗' }}</span>
                                    Passwords match
                                </div>
                            </div>
                        </Field>
                        <Field>
                            <Button type="submit" :disabled="authStore.isLoading">
                                {{ authStore.isLoading ? 'Creating Account...' : 'Create Account' }}
                            </Button>
                            <FieldDescription class="text-center">
                                Already have an account?
                                <RouterLink to="/login" class="underline underline-offset-4 hover:text-primary">
                                    Sign in
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
</template>
