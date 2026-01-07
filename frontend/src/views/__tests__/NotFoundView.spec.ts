import { describe, it, expect, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { uiStubs } from './testStubs'
import NotFound from '../NotFound.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        push: vi.fn(),
    }),
}))

describe('NotFoundView', () => {
    it('NF1: renders not found message', () => {
        const wrapper = shallowMount(NotFound, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('Page not found')
    })
})
