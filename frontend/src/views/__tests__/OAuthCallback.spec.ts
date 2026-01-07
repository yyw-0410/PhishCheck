import { describe, it, expect, vi, beforeEach } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { uiStubs } from './testStubs'
import OAuthCallback from '../OAuthCallback.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        push: vi.fn(),
    }),
    useRoute: () => ({
        query: {
            session_token: 'test-token',
            email: 'user@example.com',
            name: 'Test User',
        },
        path: '/oauth/google/callback',
    }),
    RouterLink: {
        template: '<a><slot /></a>',
    },
}))

describe('OAuthCallback', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('OA1: renders success state', async () => {
        const wrapper = shallowMount(OAuthCallback, {
            global: {
                stubs: uiStubs,
            },
        })

        await flushPromises()

        expect(wrapper.text()).toContain('Authentication Successful')
    })
})
