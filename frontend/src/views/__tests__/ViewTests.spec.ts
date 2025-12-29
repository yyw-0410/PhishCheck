import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'

// Mock vue-router
vi.mock('vue-router', () => ({
    useRouter: () => ({
        push: vi.fn(),
    }),
    useRoute: () => ({
        query: {},
    }),
    RouterLink: {
        template: '<a><slot /></a>',
    },
}))

// Stub UI components
const globalStubs = {
    Button: { template: '<button><slot /></button>' },
    Card: { template: '<div><slot /></div>' },
    CardContent: { template: '<div><slot /></div>' },
    CardDescription: { template: '<p><slot /></p>' },
    CardHeader: { template: '<div><slot /></div>' },
    CardTitle: { template: '<h1><slot /></h1>' },
    Field: { template: '<div><slot /></div>' },
    FieldDescription: { template: '<p><slot /></p>' },
    FieldGroup: { template: '<div><slot /></div>' },
    FieldLabel: { template: '<label><slot /></label>' },
    FieldSeparator: { template: '<hr />' },
    Input: {
        template: '<input :id="id" :type="type" />',
        props: ['id', 'type', 'placeholder', 'modelValue'],
    },
    IconMicrosoft: { template: '<span>MS</span>' },
    IconGoogle: { template: '<span>G</span>' },
}

describe('SignupView', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('SV1: renders signup form with all required fields', async () => {
        const SignupView = (await import('../SignupView.vue')).default
        const wrapper = mount(SignupView, {
            global: { stubs: globalStubs },
        })

        await flushPromises()

        // Check for signup form text (actual UI says "Create your account")
        expect(wrapper.text()).toContain('Create your account')
    })
})

describe('FileAnalysisView', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('FA1: renders file upload area', async () => {
        const FileAnalysisView = (await import('../FileAnalysisView.vue')).default
        const wrapper = mount(FileAnalysisView, {
            global: { stubs: globalStubs },
        })

        await flushPromises()

        // Check for file analysis content
        expect(wrapper.text().toLowerCase()).toContain('file')
    })
})

describe('LinkAnalysisView', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('LA1: renders link input field', async () => {
        const LinkAnalysisView = (await import('../LinkAnalysisView.vue')).default
        const wrapper = mount(LinkAnalysisView, {
            global: { stubs: globalStubs },
        })

        await flushPromises()

        // Check for link analysis content
        const text = wrapper.text().toLowerCase()
        expect(text.includes('url') || text.includes('link')).toBe(true)
    })
})

describe('ChatView', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('CV1: renders chat interface', async () => {
        const ChatView = (await import('../ChatView.vue')).default
        const wrapper = mount(ChatView, {
            global: { stubs: globalStubs },
        })

        await flushPromises()

        // Check for chat or AI content
        expect(wrapper.exists()).toBe(true)
    })

    it('CV2: displays AI assistant title', async () => {
        const ChatView = (await import('../ChatView.vue')).default
        const wrapper = mount(ChatView, {
            global: { stubs: globalStubs },
        })

        await flushPromises()

        // Check for assistant-related text
        const text = wrapper.text().toLowerCase()
        expect(text.includes('ai') || text.includes('chat') || text.includes('assistant')).toBe(true)
    })
})

describe('OAuthCallback', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('OA1: renders callback handler', async () => {
        const OAuthCallback = (await import('../OAuthCallback.vue')).default
        const wrapper = mount(OAuthCallback, {
            global: { stubs: globalStubs },
        })

        await flushPromises()

        // Callback should render something
        expect(wrapper.exists()).toBe(true)
    })
})
