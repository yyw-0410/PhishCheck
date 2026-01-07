import { describe, it, expect, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { uiStubs } from './testStubs'
import TermsOfServiceView from '../TermsOfServiceView.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        back: vi.fn(),
        push: vi.fn(),
    }),
}))

describe('TermsView', () => {
    it('TV1: renders terms header', () => {
        const wrapper = shallowMount(TermsOfServiceView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('Terms of Service')
    })
})
