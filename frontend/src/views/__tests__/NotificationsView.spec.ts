import { describe, it, expect, vi } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { uiStubs } from './testStubs'
import NotificationsView from '../NotificationsView.vue'

vi.mock('vue-router', () => ({
    useRouter: () => ({
        back: vi.fn(),
    }),
}))

describe('NotificationsView', () => {
    it('NV1: renders notification settings header', () => {
        const wrapper = shallowMount(NotificationsView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('Notification Settings')
    })
})
