<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowLeft, CreditCard, Check, Sparkles, Zap, Crown } from 'lucide-vue-next'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const currentPlan = ref('free')

const plans = [
    {
        id: 'free',
        name: 'Free',
        price: '$0',
        period: 'forever',
        icon: Zap,
        description: 'Perfect for getting started',
        features: [
            '10 email analyses per day',
            '5 link analyses per day',
            'Basic threat detection',
            'Community support',
        ],
        buttonText: 'Current Plan',
        buttonVariant: 'outline' as const,
        popular: false,
    },
    {
        id: 'pro',
        name: 'Pro',
        price: '$9.99',
        period: 'per month',
        icon: Sparkles,
        description: 'For power users and professionals',
        features: [
            'Unlimited email analyses',
            'Unlimited link analyses',
            'Advanced threat intelligence',
            'Priority support',
            'API access',
            'Custom reports',
        ],
        buttonText: 'Upgrade to Pro',
        buttonVariant: 'default' as const,
        popular: true,
    },
    {
        id: 'enterprise',
        name: 'Enterprise',
        price: 'Custom',
        period: 'contact us',
        icon: Crown,
        description: 'For teams and organizations',
        features: [
            'Everything in Pro',
            'Team collaboration',
            'SSO integration',
            'Dedicated support',
            'Custom integrations',
            'SLA guarantee',
        ],
        buttonText: 'Contact Sales',
        buttonVariant: 'secondary' as const,
        popular: false,
    },
]

function goBack() {
    router.back()
}

function selectPlan(planId: string) {
    if (planId === 'free') return
    if (planId === 'enterprise') {
        // TODO: Open contact form
        alert('Please contact us at enterprise@phishcheck.com')
        return
    }
    // TODO: Implement Stripe checkout
    alert('Payment integration coming soon!')
}
</script>

<template>
    <div class="min-h-screen bg-background">
        <!-- Back Button -->
        <Button 
            variant="ghost" 
            size="icon" 
            class="fixed top-4 left-4 z-50 bg-transparent hover:bg-accent/50"
            @click="goBack"
        >
            <ArrowLeft class="h-5 w-5" />
        </Button>

        <div class="container max-w-5xl mx-auto py-16 px-4">
            <div class="space-y-8">
                <!-- Header -->
                <div class="text-center space-y-2">
                    <h1 class="text-3xl font-bold">Billing & Plans</h1>
                    <p class="text-muted-foreground">Choose the plan that's right for you</p>
                </div>

                <!-- Current Plan Status -->
                <Card class="bg-muted/50">
                    <CardContent class="flex items-center justify-between py-4">
                        <div class="flex items-center gap-3">
                            <CreditCard class="h-5 w-5 text-muted-foreground" />
                            <div>
                                <p class="font-medium">Current Plan: <span class="text-primary">Free</span></p>
                                <p class="text-sm text-muted-foreground">You're using the free tier</p>
                            </div>
                        </div>
                        <Badge variant="secondary">Active</Badge>
                    </CardContent>
                </Card>

                <!-- Pricing Cards -->
                <div class="grid md:grid-cols-3 gap-6">
                    <Card 
                        v-for="plan in plans" 
                        :key="plan.id"
                        :class="[
                            'relative',
                            plan.popular ? 'border-primary shadow-lg' : '',
                            currentPlan === plan.id ? 'bg-muted/30' : ''
                        ]"
                    >
                        <!-- Popular Badge -->
                        <Badge 
                            v-if="plan.popular" 
                            class="absolute -top-3 left-1/2 -translate-x-1/2"
                        >
                            Most Popular
                        </Badge>

                        <CardHeader class="text-center pb-2">
                            <div class="mx-auto mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
                                <component :is="plan.icon" class="h-6 w-6 text-primary" />
                            </div>
                            <CardTitle>{{ plan.name }}</CardTitle>
                            <CardDescription>{{ plan.description }}</CardDescription>
                        </CardHeader>

                        <CardContent class="text-center">
                            <div class="mb-4">
                                <span class="text-4xl font-bold">{{ plan.price }}</span>
                                <span class="text-muted-foreground ml-1">{{ plan.period }}</span>
                            </div>

                            <Separator class="my-4" />

                            <ul class="space-y-3 text-left">
                                <li v-for="feature in plan.features" :key="feature" class="flex items-start gap-2">
                                    <Check class="h-5 w-5 text-green-500 shrink-0 mt-0.5" />
                                    <span class="text-sm">{{ feature }}</span>
                                </li>
                            </ul>
                        </CardContent>

                        <CardFooter>
                            <Button 
                                :variant="plan.buttonVariant"
                                class="w-full"
                                :disabled="currentPlan === plan.id"
                                @click="selectPlan(plan.id)"
                            >
                                {{ currentPlan === plan.id ? 'Current Plan' : plan.buttonText }}
                            </Button>
                        </CardFooter>
                    </Card>
                </div>

                <!-- Payment History -->
                <Card>
                    <CardHeader>
                        <CardTitle>Payment History</CardTitle>
                        <CardDescription>Your recent transactions</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div class="text-center py-8 text-muted-foreground">
                            <CreditCard class="h-12 w-12 mx-auto mb-3 opacity-50" />
                            <p>No payment history yet</p>
                            <p class="text-sm">Upgrade to Pro to see your transactions here</p>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    </div>
</template>
