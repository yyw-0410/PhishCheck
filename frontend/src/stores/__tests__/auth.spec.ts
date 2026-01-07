import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

describe('Auth Store', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
        localStorage.clear()
    })

    it('ST-AUTH-01: handles OAuth callback session', async () => {
        const { useAuthStore } = await import('@/stores/auth')
        const store = useAuthStore()

        store.handleOAuthCallback('token', {
            name: 'Test User',
            email: 'user@example.com',
            oauth_provider: 'google',
        })

        expect(store.isAuthenticated).toBe(true)
        expect(store.user?.email).toBe('user@example.com')
    })
})
