<script setup lang="ts">
import { useRouter } from 'vue-router'
import { Button } from '@/components/ui/button'

const router = useRouter()
</script>

<template>
    <div class="flex h-screen w-full flex-col items-center justify-center bg-background text-foreground">
        <div class="flex flex-col items-center space-y-6 text-center">
            <div class="space-y-2">
                <h1 class="text-9xl font-bold tracking-tighter text-primary">404</h1>
                <h2 class="text-3xl font-semibold tracking-tight">Page not found</h2>
                <p class="text-muted-foreground max-w-[500px]">
                    Sorry, we couldn't find the page you're looking for. It might have been moved, deleted, or never
                    existed.
                </p>
            </div>

            <Button @click="router.push('/')" size="lg" class="mt-8">
                Back to Home
            </Button>
        </div>
    </div>
</template>
