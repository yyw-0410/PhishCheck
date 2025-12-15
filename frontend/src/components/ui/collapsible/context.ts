import type { Ref } from 'vue'

export type CollapsibleContext = {
  open: Ref<boolean>
  toggle: () => void
}

export const COLLAPSIBLE_INJECTION_KEY = Symbol('collapsible-context')
