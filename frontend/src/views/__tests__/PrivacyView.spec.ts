import { describe, it, expect, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { uiStubs } from './testStubs'
import PrivacyPolicyView from '../PrivacyPolicyView.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        back: vi.fn(),
        push: vi.fn(),
    }),
}))

describe('PrivacyView', () => {
    it('PV1: renders privacy header', () => {
        const wrapper = shallowMount(PrivacyPolicyView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('Privacy Policy')
    })
})
