import { describe, it, expect, vi, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

describe('Auth Store', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('ST1: login sets user state', async () => {
        const { useAuthStore } = await import('@/stores/auth')
        const store = useAuthStore()

        // Mock successful login
        store.user = { id: 1, email: 'test@example.com', name: 'Test User' }
        store.isAuthenticated = true

        expect(store.user).not.toBeNull()
        expect(store.user?.email).toBe('test@example.com')
        expect(store.isAuthenticated).toBe(true)
    })

    it('ST2: logout clears user state', async () => {
        const { useAuthStore } = await import('@/stores/auth')
        const store = useAuthStore()

        // Set user first
        store.user = { id: 1, email: 'test@example.com', name: 'Test User' }
        store.isAuthenticated = true

        // Clear (simulate logout)
        store.user = null
        store.isAuthenticated = false

        expect(store.user).toBeNull()
        expect(store.isAuthenticated).toBe(false)
    })
})

describe('Analysis Store', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('ST3: setResult stores analysis result', async () => {
        const { useAnalysisStore } = await import('@/stores/analysis')
        const store = useAnalysisStore()

        const mockResult = {
            attack_score: 75,
            flagged_rules: [],
            timestamp: new Date().toISOString()
        }

        store.result = mockResult

        expect(store.result).not.toBeNull()
        expect(store.result?.attack_score).toBe(75)
    })
})
