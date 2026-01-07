import { describe, it, expect, vi, beforeEach } from 'vitest'
import { shallowMount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ref, computed } from 'vue'
import { uiStubs } from './testStubs'
import AnalysisView from '../AnalysisView.vue'

vi.mock('@/hooks/useAnalysisState', () => ({
    useAnalysisState: () => ({
        analysisResult: ref(null),
        errorMessage: ref(''),
        fileInputRef: ref(null),
        isDragActive: ref(false),
        isSubmitDisabled: computed(() => true),
        loading: ref(false),
        onDragLeave: vi.fn(),
        onDragOver: vi.fn(),
        onDrop: vi.fn(),
        onFileChange: vi.fn(),
        prettyJson: computed(() => '{}'),
        elapsedSeconds: ref(0),
        selectedFile: ref(null),
        selectedFileLabel: computed(() => ''),
        submit: vi.fn(),
        triggerFileDialog: vi.fn(),
        clearFile: vi.fn(),
        aiRecommendation: ref(''),
        aiRecommendationLoading: ref(false),
        hasMoreUrlsToScan: ref(false),
        skippedUrlCount: ref(0),
        scanMoreUrls: vi.fn(),
        scanAllUrls: vi.fn(),
        scanningMoreUrls: ref(false),
    }),
}))

vi.mock('@/hooks/useSublimeInsights', () => ({
    useSublimeInsights: () => ({
        attackScoreSummary: computed(() => ({ score: 0, label: 'Unknown' })),
        displayedUiInsightHits: computed(() => []),
        displayedUiRuleHits: computed(() => []),
        filteredUiInsightHits: computed(() => []),
        insightCounts: computed(() => ({ total: 0, critical: 0, high: 0, medium: 0, low: 0 })),
        insightSeverityFilter: ref('all'),
        ruleSummary: computed(() => ({ total: 0, flagged: 0 })),
    }),
}))

vi.mock('@/hooks/useThreatIntel', () => ({
    useThreatIntel: () => ({
        copiedHashes: ref({}),
        copiedTargets: ref({}),
        copyHash: vi.fn(),
        copyTarget: vi.fn(),
        getVtResultForFile: vi.fn(),
        openVtForFile: vi.fn(),
        urlscanKey: vi.fn(),
        urlscanVerdict: vi.fn(() => ''),
        urlscanSubmissions: ref([]),
        vtByType: ref(null),
        vtFlaggedItems: ref([]),
        virusTotalSummaries: ref([]),
        ipqsResults: ref([]),
        hybridAnalysisResults: ref([]),
    }),
}))

vi.mock('@/hooks/useParsedEmail', () => ({
    useParsedEmail: () => ({
        attachmentSummary: computed(() => null),
        senderDetails: computed(() => null),
        emailContent: computed(() => null),
        rawTextBody: ref(''),
        rawHtmlBody: ref(''),
        rawEmlContent: ref(''),
        mdmData: ref(null),
    }),
}))

vi.mock('@/utils/screenshotUtils', () => ({
    isPlaceholderScreenshot: vi.fn(() => false),
    isVerdictPending: vi.fn(() => false),
    getLiveshotUrl: vi.fn(() => ''),
}))

describe('EmlAnalyzer', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
        vi.clearAllMocks()
    })

    it('EA1: renders the EML analyzer heading', async () => {
        const wrapper = shallowMount(AnalysisView, {
            global: {
                stubs: uiStubs,
            },
        })

        await flushPromises()

        expect(wrapper.text()).toContain('EML Analyzer')
    })
})
