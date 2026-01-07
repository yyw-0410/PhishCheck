import { describe, it, expect, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { uiStubs } from './testStubs'
import SupportView from '../SupportView.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        back: vi.fn(),
        push: vi.fn(),
    }),
}))

describe('SupportView', () => {
    it('SV1: renders support header', () => {
        const wrapper = shallowMount(SupportView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('How can we help you?')
    })
})
