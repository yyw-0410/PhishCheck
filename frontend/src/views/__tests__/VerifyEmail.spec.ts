import { describe, it, expect, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { uiStubs } from './testStubs'
import EmailVerificationView from '../EmailVerificationView.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        replace: vi.fn(),
        push: vi.fn(),
    }),
    useRoute: () => ({
        query: {
            success: 'true',
            email: 'user@example.com',
        },
    }),
    RouterLink: {
        template: '<a><slot /></a>',
    },
}))

describe('VerifyEmail', () => {
    it('VE1: renders verification success message', () => {
        const wrapper = shallowMount(EmailVerificationView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('Email Verified')
    })
})
