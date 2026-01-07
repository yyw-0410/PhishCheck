import { describe, it, expect, beforeEach } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { uiStubs } from './testStubs'
import FileAnalysisView from '../FileAnalysisView.vue'

describe('FileAnalyzer', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('FA1: renders the file analysis heading', () => {
        const wrapper = shallowMount(FileAnalysisView, {
            global: {
                stubs: uiStubs,
            },
        })

        expect(wrapper.text()).toContain('File Analysis')
    })
})
