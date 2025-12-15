<script setup lang="ts">
import { computed } from "vue"
import { useRoute, RouterLink } from "vue-router"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"

const route = useRoute()

const success = computed(() => route.query.success === "true")
const email = computed(() => route.query.email as string || "")
const error = computed(() => route.query.error as string || "")
</script>

<template>
    <div class="flex items-center justify-center min-h-[60vh] py-12">
        <Card class="w-full max-w-md">
            <CardHeader class="text-center">
                <div v-if="success" class="mb-4 text-6xl">✅</div>
                <div v-else class="mb-4 text-6xl">❌</div>
                <CardTitle class="text-xl">
                    {{ success ? "Email Verified!" : "Verification Failed" }}
                </CardTitle>
            </CardHeader>
            <CardContent class="text-center space-y-4">
                <template v-if="success">
                    <p class="text-muted-foreground">
                        Your email <strong>{{ email }}</strong> has been verified successfully.
                    </p>
                    <p class="text-muted-foreground">
                        You can now enjoy all features of PhishCheck.
                    </p>
                    <RouterLink to="/">
                        <Button class="w-full">Go to Dashboard</Button>
                    </RouterLink>
                </template>
                <template v-else>
                    <p class="text-muted-foreground">
                        <template v-if="error === 'invalid_token'">
                            This verification link is invalid or has expired.
                        </template>
                        <template v-else>
                            Something went wrong during verification.
                        </template>
                    </p>
                    <p class="text-sm text-muted-foreground">
                        Please try logging in and requesting a new verification email.
                    </p>
                    <RouterLink to="/login">
                        <Button variant="outline" class="w-full">Go to Login</Button>
                    </RouterLink>
                </template>
            </CardContent>
        </Card>
    </div>
</template>
