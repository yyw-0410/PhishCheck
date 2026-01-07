import { describe, it, expect, vi, afterEach } from 'vitest'
import { shallowMount } from '@vue/test-utils'
import { uiStubs } from './testStubs'
import AIChatWidget from '@/components/chat/AIChatWidget.vue'

const chatStore = {
    messages: [],
    currentQuestions: ['What is phishing?'],
    chatMode: 'general',
    isLoading: false,
    error: null,
    fetchSuggestedQuestions: vi.fn(),
    sendMessage: vi.fn().mockResolvedValue(undefined),
    startNewChat: vi.fn(),
    startAnalysisChat: vi.fn(),
}

const analysisStore = {
    hasAnyAnalysis: false,
}

const authStore = {
    isAuthenticated: true,
    user: { avatar: '' },
}

vi.mock('@/stores/chat', () => ({
    useChatStore: () => chatStore,
}))

vi.mock('@/stores/analysis', () => ({
    useAnalysisStore: () => analysisStore,
}))

vi.mock('@/stores/auth', () => ({
    useAuthStore: () => authStore,
}))

describe('AIChatOverlay', () => {
    const originalFetch = globalThis.fetch

    afterEach(() => {
        globalThis.fetch = originalFetch
    })

    it('AI1: opens the AI chat overlay', async () => {
        globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) }) as typeof fetch

        const wrapper = shallowMount(AIChatWidget, {
            global: {
                stubs: {
                    ...uiStubs,
                    Teleport: true,
                    Transition: false,
                },
            },
        })

        const openButton = wrapper.find('button')
        expect(openButton.exists()).toBe(true)

        await openButton.trigger('click')
        await wrapper.vm.$nextTick()

        expect(wrapper.text()).toContain('PhishCheck AI')
    })
})
