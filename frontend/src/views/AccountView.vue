<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowLeft, User, Shield, Trash2, Link2, Unlink, Camera, X } from 'lucide-vue-next'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Separator } from '@/components/ui/separator'
import { Badge } from '@/components/ui/badge'
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog'
import { useAuthStore } from '@/stores/auth'
import IconGoogle from '@/components/icons/IconGoogle.vue'
import IconMicrosoft from '@/components/icons/IconMicrosoft.vue'

const router = useRouter()
const authStore = useAuthStore()

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000"

const user = computed(() => authStore.user)
const isOAuthUser = computed(() => !!user.value?.oauth_provider)

// Check which accounts are connected (only for non-OAuth users who linked an account)
const hasLinkedAccount = computed(() => !isOAuthUser.value && !!user.value?.oauth_provider)
const connectedGoogle = computed(() => user.value?.oauth_provider === 'google')
const connectedMicrosoft = computed(() => user.value?.oauth_provider === 'microsoft')
const connectedEmail = computed(() => user.value?.oauth_email || '')
const isVerified = computed(() => user.value?.is_verified !== false)

// Form state
const name = ref(user.value?.name || '')
const email = ref(user.value?.email || '')
const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')

// Avatar editing
const showAvatarDialog = ref(false)
const avatarUrl = ref(user.value?.avatar || '')
const avatarPreview = ref(user.value?.avatar || '')
const fileInput = ref<HTMLInputElement | null>(null)

const isUpdating = ref(false)
const updateMessage = ref('')
const errorMessage = ref('')

function goBack() {
    router.back()
}

function openAvatarDialog() {
    avatarUrl.value = user.value?.avatar || ''
    avatarPreview.value = user.value?.avatar || ''
    showAvatarDialog.value = true
}

function handleFileSelect(event: Event) {
    const target = event.target as HTMLInputElement
    const file = target.files?.[0]
    if (file) {
        // Convert to base64 for preview and storage
        const reader = new FileReader()
        reader.onload = (e) => {
            const result = e.target?.result as string
            avatarPreview.value = result
            avatarUrl.value = result
        }
        reader.readAsDataURL(file)
    }
}

function handleUrlChange() {
    avatarPreview.value = avatarUrl.value
}

function generateAvatar() {
    // Generate avatar using UI Avatars service
    const encodedName = encodeURIComponent(name.value || user.value?.name || 'User')
    avatarUrl.value = `https://ui-avatars.com/api/?name=${encodedName}&background=random&size=200`
    avatarPreview.value = avatarUrl.value
}

function saveAvatar() {
    if (user.value) {
        user.value.avatar = avatarUrl.value
        // Update localStorage
        localStorage.setItem('user', JSON.stringify(user.value))
        updateMessage.value = 'Profile picture updated!'
        showAvatarDialog.value = false
    }
}

function removeAvatar() {
    avatarUrl.value = ''
    avatarPreview.value = ''
}

async function updateProfile() {
    isUpdating.value = true
    updateMessage.value = ''
    errorMessage.value = ''

    // TODO: Implement API call to update profile
    setTimeout(() => {
        updateMessage.value = 'Profile updated successfully!'
        isUpdating.value = false
    }, 1000)
}

async function changePassword() {
    errorMessage.value = ''
    updateMessage.value = ''

    if (newPassword.value.length < 8) {
        errorMessage.value = 'Password must be at least 8 characters'
        return
    }

    if (newPassword.value !== confirmPassword.value) {
        errorMessage.value = 'Passwords do not match'
        return
    }

    isUpdating.value = true
    // TODO: Implement API call to change password
    setTimeout(() => {
        updateMessage.value = 'Password changed successfully!'
        currentPassword.value = ''
        newPassword.value = ''
        confirmPassword.value = ''
        isUpdating.value = false
    }, 1000)
}

function connectGoogle() {
    // Redirect to Google OAuth with link_account flag
    window.location.href = `${API_BASE_URL}/api/auth/google/login?action=link`
}

function connectMicrosoft() {
    // Redirect to Microsoft OAuth with link_account flag
    window.location.href = `${API_BASE_URL}/api/auth/microsoft/login?action=link`
}

async function disconnectAccount(provider: string) {
    if (confirm(`Are you sure you want to disconnect your ${provider} account?`)) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/auth/disconnect-oauth`, {
                method: 'POST',
                credentials: 'include'
            })

            if (response.ok) {
                const updatedUser = await response.json()
                // Update auth store
                if (authStore.user) {
                    authStore.user.oauth_provider = undefined
                    authStore.user.oauth_email = undefined
                    localStorage.setItem('user', JSON.stringify(authStore.user))
                }
                updateMessage.value = `${provider} account disconnected`
            } else {
                const data = await response.json()
                errorMessage.value = data.detail || 'Failed to disconnect'
            }
        } catch {
            errorMessage.value = 'Network error'
        }
    }
}

async function deleteAccount() {
    if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
        // TODO: Implement API call to delete account
        await authStore.logout()
        router.push('/')
    }
}

function getInitials(name: string) {
    return name
        .split(' ')
        .map(n => n[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
}
</script>

<template>
    <div class="min-h-screen bg-background">
        <!-- Back Button -->
        <Button variant="ghost" size="icon" class="fixed top-4 left-4 z-50 bg-transparent hover:bg-accent/50"
            @click="goBack">
            <ArrowLeft class="h-5 w-5" />
        </Button>

        <div class="container max-w-2xl mx-auto py-16 px-4">
            <div class="space-y-6">
                <!-- Header -->
                <div class="text-center space-y-2">
                    <h1 class="text-3xl font-bold">Account Settings</h1>
                    <p class="text-muted-foreground">Manage your account information and preferences</p>
                </div>

                <!-- Success/Error Message -->
                <div v-if="updateMessage" class="rounded-md bg-green-500/15 p-3 text-sm text-green-600 text-center">
                    {{ updateMessage }}
                </div>
                <div v-if="errorMessage" class="rounded-md bg-destructive/15 p-3 text-sm text-destructive text-center">
                    {{ errorMessage }}
                </div>

                <!-- Profile Card -->
                <Card>
                    <CardHeader>
                        <CardTitle class="flex items-center gap-2">
                            <User class="h-5 w-5" />
                            Profile Information
                        </CardTitle>
                        <CardDescription>Update your personal details</CardDescription>
                    </CardHeader>
                    <CardContent class="space-y-6">
                        <!-- Avatar Section -->
                        <div class="flex items-center gap-4">
                            <div class="relative group">
                                <Avatar class="h-20 w-20">
                                    <AvatarImage :src="user?.avatar || ''" :alt="user?.name || ''" />
                                    <AvatarFallback class="text-lg">
                                        {{ user?.name ? getInitials(user.name) : 'U' }}
                                    </AvatarFallback>
                                </Avatar>
                                <!-- Edit overlay -->
                                <button @click="openAvatarDialog"
                                    class="absolute inset-0 flex items-center justify-center bg-black/50 rounded-full opacity-0 group-hover:opacity-100 transition-opacity cursor-pointer">
                                    <Camera class="h-6 w-6 text-white" />
                                </button>
                            </div>
                            <div class="space-y-1">
                                <p class="font-medium">{{ user?.name }}</p>
                                <p class="text-sm text-muted-foreground">{{ user?.email }}</p>
                                <Badge v-if="isOAuthUser" variant="secondary" class="mt-1">
                                    {{ user?.oauth_provider === 'google' ? 'Google' : 'Microsoft' }} Account
                                </Badge>
                                <Button variant="link" size="sm" class="h-auto p-0 text-xs" @click="openAvatarDialog">
                                    Change photo
                                </Button>
                            </div>
                        </div>

                        <Separator />

                        <!-- Name & Email -->
                        <div class="grid gap-4">
                            <div class="space-y-2">
                                <Label for="name">Full Name</Label>
                                <Input id="name" v-model="name" placeholder="Your name" />
                            </div>
                            <div class="space-y-2">
                                <Label for="email">Email Address</Label>
                                <Input id="email" v-model="email" type="email" placeholder="your@email.com"
                                    :disabled="isOAuthUser" />
                                <p v-if="isOAuthUser" class="text-xs text-muted-foreground">
                                    Email cannot be changed for OAuth accounts
                                </p>
                            </div>
                        </div>

                        <Button @click="updateProfile" :disabled="isUpdating" class="w-full">
                            {{ isUpdating ? 'Saving...' : 'Save Changes' }}
                        </Button>
                    </CardContent>
                </Card>

                <!-- Password Card (only for non-OAuth users) -->
                <Card v-if="!isOAuthUser">
                    <CardHeader>
                        <CardTitle class="flex items-center gap-2">
                            <Shield class="h-5 w-5" />
                            Change Password
                        </CardTitle>
                        <CardDescription>Update your password to keep your account secure</CardDescription>
                    </CardHeader>
                    <CardContent class="space-y-4">
                        <div class="space-y-2">
                            <Label for="current-password">Current Password</Label>
                            <Input id="current-password" v-model="currentPassword" type="password" />
                        </div>
                        <div class="space-y-2">
                            <Label for="new-password">New Password</Label>
                            <Input id="new-password" v-model="newPassword" type="password" />
                        </div>
                        <div class="space-y-2">
                            <Label for="confirm-password">Confirm New Password</Label>
                            <Input id="confirm-password" v-model="confirmPassword" type="password" />
                        </div>
                        <Button @click="changePassword" :disabled="isUpdating" variant="secondary" class="w-full">
                            {{ isUpdating ? 'Changing...' : 'Change Password' }}
                        </Button>
                    </CardContent>
                </Card>

                <!-- Connected Accounts Card (ONLY for email/password users to link ONE OAuth account) -->
                <Card v-if="!isOAuthUser">
                    <CardHeader>
                        <CardTitle class="flex items-center gap-2">
                            <Link2 class="h-5 w-5" />
                            Connect Account
                        </CardTitle>
                        <CardDescription>
                            Link your Google or Microsoft account to access your emails for analysis
                        </CardDescription>
                    </CardHeader>
                    <CardContent class="space-y-4">
                        <!-- If already connected to one provider -->
                        <template v-if="hasLinkedAccount">
                            <!-- Show connected account -->
                            <div
                                class="flex items-center justify-between p-3 rounded-lg border border-green-500/50 bg-green-500/5">
                                <div class="flex items-center gap-3">
                                    <div class="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                                        <IconGoogle v-if="connectedGoogle" class="h-5 w-5" />
                                        <IconMicrosoft v-else class="h-5 w-5" />
                                    </div>
                                    <div>
                                        <p class="font-medium">{{ connectedGoogle ? 'Google' : 'Microsoft' }}</p>
                                        <p class="text-sm text-green-600">{{ connectedEmail || 'Connected' }}</p>
                                    </div>
                                </div>
                                <Button variant="outline" size="sm"
                                    @click="disconnectAccount(connectedGoogle ? 'Google' : 'Microsoft')">
                                    <Unlink class="h-4 w-4 mr-1" />
                                    Disconnect
                                </Button>
                            </div>
                            <p class="text-xs text-muted-foreground text-center">
                                You can only connect one account at a time for email access.
                            </p>
                        </template>

                        <!-- If not connected, show both options -->
                        <template v-else>
                            <!-- Verification required notice -->
                            <div v-if="!isVerified"
                                class="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-300 text-sm mb-3">
                                ⚠️ Please verify your email to connect accounts.
                            </div>
                            <div class="flex items-center justify-between p-3 rounded-lg border transition-colors"
                                :class="isVerified ? 'hover:bg-muted/50' : 'opacity-60'">
                                <div class="flex items-center gap-3">
                                    <div class="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                                        <IconGoogle class="h-5 w-5" />
                                    </div>
                                    <div>
                                        <p class="font-medium">Google</p>
                                        <p class="text-sm text-muted-foreground">Access Gmail emails</p>
                                    </div>
                                </div>
                                <Button variant="outline" size="sm" @click="connectGoogle" :disabled="!isVerified">
                                    <Link2 class="h-4 w-4 mr-1" />
                                    Connect
                                </Button>
                            </div>

                            <div class="flex items-center justify-between p-3 rounded-lg border transition-colors"
                                :class="isVerified ? 'hover:bg-muted/50' : 'opacity-60'">
                                <div class="flex items-center gap-3">
                                    <div class="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                                        <IconMicrosoft class="h-5 w-5" />
                                    </div>
                                    <div>
                                        <p class="font-medium">Microsoft</p>
                                        <p class="text-sm text-muted-foreground">Access Outlook emails</p>
                                    </div>
                                </div>
                                <Button variant="outline" size="sm" @click="connectMicrosoft" :disabled="!isVerified">
                                    <Link2 class="h-4 w-4 mr-1" />
                                    Connect
                                </Button>
                            </div>
                            <p class="text-xs text-muted-foreground text-center">
                                {{ isVerified ? 'Connect one account to analyze emails directly from your inbox.' :
                                'Verify your email first to enable account connections.' }}
                            </p>
                        </template>
                    </CardContent>
                </Card>

                <!-- Danger Zone -->
                <Card class="border-destructive/50">
                    <CardHeader>
                        <CardTitle class="flex items-center gap-2 text-destructive">
                            <Trash2 class="h-5 w-5" />
                            Danger Zone
                        </CardTitle>
                        <CardDescription>Irreversible actions for your account</CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="font-medium">Delete Account</p>
                                <p class="text-sm text-muted-foreground">
                                    Permanently delete your account and all associated data
                                </p>
                            </div>
                            <Button variant="destructive" @click="deleteAccount">
                                Delete Account
                            </Button>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>

        <!-- Avatar Edit Dialog -->
        <Dialog v-model:open="showAvatarDialog">
            <DialogContent class="sm:max-w-md">
                <DialogHeader>
                    <DialogTitle>Change Profile Picture</DialogTitle>
                    <DialogDescription>
                        Upload a new photo or enter an image URL
                    </DialogDescription>
                </DialogHeader>

                <div class="space-y-4 py-4">
                    <!-- Preview -->
                    <div class="flex justify-center">
                        <div class="relative">
                            <Avatar class="h-32 w-32">
                                <AvatarImage :src="avatarPreview" :alt="user?.name || ''" />
                                <AvatarFallback class="text-2xl">
                                    {{ user?.name ? getInitials(user.name) : 'U' }}
                                </AvatarFallback>
                            </Avatar>
                            <button v-if="avatarPreview" @click="removeAvatar"
                                class="absolute -top-2 -right-2 p-1 bg-destructive text-destructive-foreground rounded-full hover:bg-destructive/90">
                                <X class="h-4 w-4" />
                            </button>
                        </div>
                    </div>

                    <!-- Upload Button -->
                    <div class="space-y-2">
                        <Label>Upload from device</Label>
                        <input ref="fileInput" type="file" accept="image/*" class="hidden" @change="handleFileSelect" />
                        <Button variant="outline" class="w-full" @click="fileInput?.click()">
                            <Camera class="h-4 w-4 mr-2" />
                            Choose Photo
                        </Button>
                    </div>

                    <!-- URL Input -->
                    <div class="space-y-2">
                        <Label for="avatar-url">Or enter image URL</Label>
                        <Input id="avatar-url" v-model="avatarUrl" placeholder="https://example.com/photo.jpg"
                            @blur="handleUrlChange" @keyup.enter="handleUrlChange" />
                    </div>

                    <!-- Generate Avatar -->
                    <Button variant="secondary" class="w-full" @click="generateAvatar">
                        Generate Avatar from Name
                    </Button>
                </div>

                <DialogFooter class="gap-2 sm:gap-0">
                    <Button variant="outline" @click="showAvatarDialog = false">
                        Cancel
                    </Button>
                    <Button @click="saveAvatar">
                        Save Photo
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    </div>
</template>
