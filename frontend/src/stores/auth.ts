import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import { API_BASE_URL } from '@/services/api'
import { useAnalysisStore } from './analysis'
import { useChatStore } from './chat'

const API_BASE = `${API_BASE_URL}/api`

interface User {
    id: number
    name: string
    email: string
    avatar?: string
    oauth_provider?: string
    oauth_email?: string  // The connected email (may differ from login email)
    is_verified?: boolean
}

/**
 * Pinia store for authentication state management.
 * 
 * Handles user sessions, login/register actions, OAuth callbacks,
 * and persistent state synchronization.
 */
export const useAuthStore = defineStore('auth', () => {
    const isAuthenticated = ref(false)
    const user = ref<User | null>(null)
    const sessionToken = ref<string | null>(null)  // Kept for backward compatibility
    const isLoading = ref(false)
    const error = ref<string | null>(null)

    // Initialize from localStorage on store creation (user data only)
    // Token is now in httpOnly cookie - will be validated on first API call
    const savedUser = localStorage.getItem('user')
    if (savedUser) {
        user.value = JSON.parse(savedUser)
        isAuthenticated.value = true  // Will be verified by validateSession()
    }

    // Computed
    const emailProvider = computed(() => user.value?.oauth_provider as 'microsoft' | 'google' | null)

    // Helper to save session (user data only - token is now in httpOnly cookie)
    function saveSession(token: string, userData: User) {
        sessionToken.value = token  // Keep for backward compatibility display
        user.value = userData
        isAuthenticated.value = true
        // Only store user data, not the token (token is in httpOnly cookie)
        localStorage.setItem('user', JSON.stringify(userData))
    }

    // Helper to clear session
    function clearSession() {
        sessionToken.value = null
        user.value = null
        isAuthenticated.value = false
        localStorage.removeItem('user')
    }

    /**
     * Register a new user with email and password.
     * @param name - Display name
     * @param email - User email
     * @param password - User password
     * @returns True if successful
     */
    async function register(name: string, email: string, password: string): Promise<boolean> {
        isLoading.value = true
        error.value = null

        try {
            const response = await fetch(`${API_BASE}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, email, password }),
                credentials: 'include'  // Send and receive cookies
            })

            const data = await response.json()

            if (!response.ok) {
                error.value = data.detail || 'Registration failed'
                return false
            }

            saveSession(data.session_token, data.user)
            return true
        } catch (e) {
            error.value = 'Network error. Please try again.'
            return false
        } finally {
            isLoading.value = false
        }
    }

    /**
     * Login with email and password.
     * @param email - User email
     * @param password - User password
     * @returns True if successful
     */
    async function login(email: string, password: string): Promise<boolean> {
        isLoading.value = true
        error.value = null

        try {
            const response = await fetch(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
                credentials: 'include'  // Send and receive cookies
            })

            const data = await response.json()

            if (!response.ok) {
                error.value = data.detail || 'Login failed'
                return false
            }

            saveSession(data.session_token, data.user)
            return true
        } catch (e) {
            error.value = 'Network error. Please try again.'
            return false
        } finally {
            isLoading.value = false
        }
    }

    // Handle OAuth callback
    function handleOAuthCallback(token: string, userData: { name: string; email: string; avatar?: string; oauth_provider?: string }) {
        const userObj: User = {
            id: 0, // Will be set properly when we validate
            name: userData.name,
            email: userData.email,
            avatar: userData.avatar,
            oauth_provider: userData.oauth_provider
        }
        saveSession(token, userObj)
    }

    // Validate current session
    async function validateSession(): Promise<boolean> {
        // With httpOnly cookies, we don't have access to the token in JavaScript.
        // Instead, check if there's stored user data from a previous login.
        // The cookie will be sent automatically with the request.
        if (!user.value && !localStorage.getItem('user')) {
            return false
        }

        try {
            const response = await fetch(`${API_BASE}/auth/validate`, {
                method: 'POST',
                credentials: 'include'  // Cookie will be sent automatically
            })

            const data = await response.json()

            if (data.valid && data.user) {
                user.value = data.user
                isAuthenticated.value = true
                localStorage.setItem('user', JSON.stringify(data.user))
                return true
            } else {
                clearSession()
                return false
            }
        } catch (e) {
            // Keep session if network error (offline mode)
            return isAuthenticated.value
        }
    }

    // Logout
    async function logout(): Promise<void> {
        try {
            await fetch(`${API_BASE}/auth/logout`, {
                method: 'POST',
                credentials: 'include'  // Cookie will be sent automatically
            })
        } catch (e) {
            // Ignore errors, clear session anyway
        }
        clearSession()

        // Clear analysis and chat data
        const analysisStore = useAnalysisStore()
        const chatStore = useChatStore()
        analysisStore.resetAll()
        chatStore.clearChat()
    }

    return {
        isAuthenticated,
        user,
        emailProvider,
        sessionToken,
        isLoading,
        error,
        register,
        login,
        handleOAuthCallback,
        validateSession,
        logout
    }
})
