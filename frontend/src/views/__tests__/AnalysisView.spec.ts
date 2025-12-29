import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ref, computed } from 'vue'

// Mock all hooks used by AnalysisView
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

// Stub complex UI components
const globalStubs = {
    Dialog: { template: '<div><slot /></div>' },
    DialogContent: { template: '<div><slot /></div>' },
    DialogHeader: { template: '<div><slot /></div>' },
    DialogTitle: { template: '<h2><slot /></h2>' },
    Button: { template: '<button><slot /></button>' },
    JsonTreeNode: { template: '<div></div>' },
    // Lucide icons
    UploadCloud: { template: '<span />' },
    FileText: { template: '<span />' },
    ShieldAlert: { template: '<span />' },
    ShieldCheck: { template: '<span />' },
    Search: { template: '<span />' },
    ExternalLink: { template: '<span />' },
    ChevronDown: { template: '<span />' },
    ChevronRight: { template: '<span />' },
    AlertTriangle: { template: '<span />' },
    CheckCircle2: { template: '<span />' },
    XCircle: { template: '<span />' },
    Copy: { template: '<span />' },
    Check: { template: '<span />' },
    Bot: { template: '<span />' },
    Mail: { template: '<span />' },
    Loader2: { template: '<span />' },
    Globe: { template: '<span />' },
    Lightbulb: { template: '<span />' },
    Server: { template: '<span />' },
    Wifi: { template: '<span />' },
    Code: { template: '<span />' },
    FileCode: { template: '<span />' },
    Database: { template: '<span />' },
    Download: { template: '<span />' },
    KeyRound: { template: '<span />' },
    ArrowRight: { template: '<span />' },
    Eye: { template: '<span />' },
    Trash2: { template: '<span />' },
    Plus: { template: '<span />' },
    Monitor: { template: '<span />' },
    RefreshCw: { template: '<span />' },
}

describe('AnalysisView', () => {
    beforeEach(() => {
        setActivePinia(createPinia())
        vi.clearAllMocks()
    })

    it('FE-ANALYSIS-01: renders upload area when no analysis in progress', async () => {
        const AnalysisView = (await import('../AnalysisView.vue')).default
        const wrapper = mount(AnalysisView, {
            global: {
                stubs: globalStubs,
            },
        })

        await flushPromises()

        // Check for upload instruction text (matches actual UI)
        expect(wrapper.text()).toContain('Drop your .eml file here')
    })

    it('FE-ANALYSIS-02: contains analyze button', async () => {
        const AnalysisView = (await import('../AnalysisView.vue')).default
        const wrapper = mount(AnalysisView, {
            global: {
                stubs: globalStubs,
            },
        })

        await flushPromises()

        // Check for analyze button text
        expect(wrapper.text()).toContain('Analyze File')
    })

    it('FE-ANALYSIS-03: displays EML Analyzer heading', async () => {
        const AnalysisView = (await import('../AnalysisView.vue')).default
        const wrapper = mount(AnalysisView, {
            global: {
                stubs: globalStubs,
            },
        })

        await flushPromises()

        // Check for main heading
        expect(wrapper.text()).toContain('EML Analyzer')
    })
})

