import { describe, it, expect, beforeEach } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { uiStubs } from './testStubs'
import LinkAnalysisView from '../LinkAnalysisView.vue'

describe('LinkAnalyzer', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('LA1: renders the link analysis heading', () => {
        const wrapper = shallowMount(LinkAnalysisView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('Link Analysis')
    })
})
