<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowLeft, Bell, Mail, Shield, Megaphone, Smartphone } from 'lucide-vue-next'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'

const router = useRouter()

// Notification settings
const emailNotifications = ref({
    securityAlerts: true,
    weeklyReport: false,
    productUpdates: true,
    tips: false,
})

const pushNotifications = ref({
    threatDetected: true,
    analysisComplete: true,
    securityAlerts: true,
})

const isSaving = ref(false)
const saveMessage = ref('')

function goBack() {
    router.back()
}

async function saveSettings() {
    isSaving.value = true
    saveMessage.value = ''
    
    // TODO: Implement API call to save notification settings
    setTimeout(() => {
        saveMessage.value = 'Settings saved successfully!'
        isSaving.value = false
        
        setTimeout(() => {
            saveMessage.value = ''
        }, 3000)
    }, 1000)
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

        <div class="container max-w-2xl mx-auto py-16 px-4">
            <div class="space-y-6">
                <!-- Header -->
                <div class="text-center space-y-2">
                    <h1 class="text-3xl font-bold">Notification Settings</h1>
                    <p class="text-muted-foreground">Manage how and when you receive notifications</p>
                </div>

                <!-- Success Message -->
                <div v-if="saveMessage" class="rounded-md bg-green-500/15 p-3 text-sm text-green-600 text-center">
                    {{ saveMessage }}
                </div>

                <!-- Email Notifications -->
                <Card>
                    <CardHeader>
                        <CardTitle class="flex items-center gap-2">
                            <Mail class="h-5 w-5" />
                            Email Notifications
                        </CardTitle>
                        <CardDescription>Choose what emails you'd like to receive</CardDescription>
                    </CardHeader>
                    <CardContent class="space-y-6">
                        <div class="flex items-center justify-between">
                            <div class="space-y-0.5">
                                <Label class="flex items-center gap-2">
                                    <Shield class="h-4 w-4 text-red-500" />
                                    Security Alerts
                                </Label>
                                <p class="text-sm text-muted-foreground">
                                    Get notified about suspicious activity on your account
                                </p>
                            </div>
                            <Switch v-model:checked="emailNotifications.securityAlerts" />
                        </div>

                        <Separator />

                        <div class="flex items-center justify-between">
                            <div class="space-y-0.5">
                                <Label class="flex items-center gap-2">
                                    <Bell class="h-4 w-4 text-blue-500" />
                                    Weekly Security Report
                                </Label>
                                <p class="text-sm text-muted-foreground">
                                    Receive a weekly summary of your security analyses
                                </p>
                            </div>
                            <Switch v-model:checked="emailNotifications.weeklyReport" />
                        </div>

                        <Separator />

                        <div class="flex items-center justify-between">
                            <div class="space-y-0.5">
                                <Label class="flex items-center gap-2">
                                    <Megaphone class="h-4 w-4 text-purple-500" />
                                    Product Updates
                                </Label>
                                <p class="text-sm text-muted-foreground">
                                    Learn about new features and improvements
                                </p>
                            </div>
                            <Switch v-model:checked="emailNotifications.productUpdates" />
                        </div>

                        <Separator />

                        <div class="flex items-center justify-between">
                            <div class="space-y-0.5">
                                <Label>Security Tips & Best Practices</Label>
                                <p class="text-sm text-muted-foreground">
                                    Occasional tips to help you stay safe online
                                </p>
                            </div>
                            <Switch v-model:checked="emailNotifications.tips" />
                        </div>
                    </CardContent>
                </Card>

                <!-- Push Notifications -->
                <Card>
                    <CardHeader>
                        <CardTitle class="flex items-center gap-2">
                            <Smartphone class="h-5 w-5" />
                            Push Notifications
                        </CardTitle>
                        <CardDescription>Real-time alerts in your browser</CardDescription>
                    </CardHeader>
                    <CardContent class="space-y-6">
                        <div class="flex items-center justify-between">
                            <div class="space-y-0.5">
                                <Label>Threat Detected</Label>
                                <p class="text-sm text-muted-foreground">
                                    Immediate alert when a phishing threat is detected
                                </p>
                            </div>
                            <Switch v-model:checked="pushNotifications.threatDetected" />
                        </div>

                        <Separator />

                        <div class="flex items-center justify-between">
                            <div class="space-y-0.5">
                                <Label>Analysis Complete</Label>
                                <p class="text-sm text-muted-foreground">
                                    Notification when your analysis is ready
                                </p>
                            </div>
                            <Switch v-model:checked="pushNotifications.analysisComplete" />
                        </div>

                        <Separator />

                        <div class="flex items-center justify-between">
                            <div class="space-y-0.5">
                                <Label>Security Alerts</Label>
                                <p class="text-sm text-muted-foreground">
                                    Important security notifications
                                </p>
                            </div>
                            <Switch v-model:checked="pushNotifications.securityAlerts" />
                        </div>
                    </CardContent>
                </Card>

                <!-- Save Button -->
                <Button @click="saveSettings" :disabled="isSaving" class="w-full">
                    {{ isSaving ? 'Saving...' : 'Save Preferences' }}
                </Button>
            </div>
        </div>
    </div>
</template>
