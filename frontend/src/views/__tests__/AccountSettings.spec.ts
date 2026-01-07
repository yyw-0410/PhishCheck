import { describe, it, expect, vi, beforeEach } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { uiStubs } from './testStubs'
import AccountView from '../AccountView.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        back: vi.fn(),
        push: vi.fn(),
    }),
}))

describe('AccountSettings', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('AS1: renders account settings heading', async () => {
        const { useAuthStore } = await import('@/stores/auth')
        const authStore = useAuthStore()
        authStore.user = { id: 1, name: 'Test User', email: 'user@example.com' }
        authStore.isAuthenticated = true

        const wrapper = shallowMount(AccountView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('Account Settings')
    })
})
