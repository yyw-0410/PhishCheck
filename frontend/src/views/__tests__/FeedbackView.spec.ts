import { describe, it, expect, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { uiStubs } from './testStubs'
import FeedbackView from '../FeedbackView.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        back: vi.fn(),
    }),
}))

describe('FeedbackView', () => {
    it('FV1: renders feedback header', () => {
        const wrapper = shallowMount(FeedbackView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('Feedback & Suggestions')
    })
})
