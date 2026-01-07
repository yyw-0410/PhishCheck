import { describe, it, expect } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { uiStubs } from './testStubs'
import SignupView from '../SignupView.vue'

describe('SignUpView', () => {
    it('SV1: renders signup content', () => {
        const wrapper = shallowMount(SignupView, {
            global: {
                stubs: {
                    ...uiStubs,
                    SignupForm: { template: '<div>Create your account</div>' },
                },
            },
        })

        expect(wrapper.text()).toContain('Create your account')
    })
})
