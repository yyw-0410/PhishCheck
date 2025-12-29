import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'

// Mock vue-router
vi.mock('vue-router', () => ({
    useRouter: () => ({
        push: vi.fn(),
    }),
    RouterLink: {
        template: '<a><slot /></a>',
    },
}))

// Stub UI components to avoid deep rendering issues
const stubComponents = {
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
        template: '<input :id="id" :type="type" :placeholder="placeholder" :value="modelValue" @input="$emit(\'update:modelValue\', $event.target.value)" />',
        props: ['id', 'type', 'placeholder', 'modelValue'],
        emits: ['update:modelValue'],
    },
    IconMicrosoft: { template: '<span>MS</span>' },
    IconGoogle: { template: '<span>G</span>' },
}

describe('LoginView', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('FE-LOGIN-01: renders login form with email and password inputs', async () => {
        const LoginView = (await import('../LoginView.vue')).default
        const wrapper = mount(LoginView, {
            global: {
                stubs: stubComponents,
            },
        })

        // Check for email input
        const emailInput = wrapper.find('input#email')
        expect(emailInput.exists()).toBe(true)
        expect(emailInput.attributes('type')).toBe('email')

        // Check for password input
        const passwordInput = wrapper.find('input#password')
        expect(passwordInput.exists()).toBe(true)
        expect(passwordInput.attributes('type')).toBe('password')
    })

    it('FE-LOGIN-02: displays OAuth login buttons', async () => {
        const LoginView = (await import('../LoginView.vue')).default
        const wrapper = mount(LoginView, {
            global: {
                stubs: stubComponents,
            },
        })

        const buttons = wrapper.findAll('button')
        const buttonTexts = buttons.map((b) => b.text())

        // Check for OAuth buttons
        expect(buttonTexts.some((t) => t.includes('Microsoft'))).toBe(true)
        expect(buttonTexts.some((t) => t.includes('Google'))).toBe(true)
    })

    it('FE-LOGIN-03: shows error message when authStore has error', async () => {
        const LoginView = (await import('../LoginView.vue')).default
        const { useAuthStore } = await import('@/stores/auth')

        const wrapper = mount(LoginView, {
            global: {
                stubs: stubComponents,
            },
        })

        // Set error in auth store
        const authStore = useAuthStore()
        authStore.error = 'Invalid email or password'

        await wrapper.vm.$nextTick()

        // Check error message is displayed
        const errorDiv = wrapper.find('.bg-destructive\\/10')
        expect(errorDiv.exists()).toBe(true)
        expect(errorDiv.text()).toContain('Invalid email or password')
    })
})
