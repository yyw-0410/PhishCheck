import { describe, it, expect, vi, beforeEach } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { uiStubs } from './testStubs'
import BillingView from '../BillingView.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        back: vi.fn(),
    }),
}))

describe('BillingView', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('BV1: renders billing header', () => {
        const wrapper = shallowMount(BillingView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('Billing & Plans')
    })
})
