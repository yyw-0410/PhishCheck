import { describe, it, expect, beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

describe('Analysis Store', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
    })

    it('ST-ANALYSIS-01: sets link analysis result', async () => {
        const { useAnalysisStore } = await import('@/stores/analysis')
        const store = useAnalysisStore()

        const mockResult = {
            risk_score: 12,
            overall_verdict: 'clean',
        } as any

        store.setLinkAnalysisResult(mockResult)

        expect(store.activeAnalysisType).toBe('link')
        expect(store.linkAnalysisResult).toStrictEqual(mockResult)
    })
})
