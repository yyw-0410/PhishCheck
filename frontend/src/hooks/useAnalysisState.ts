import { computed, ref } from 'vue'
import { useAnalysisStore } from '@/stores/analysis'
import type { CombinedAnalysisResult, UrlscanSubmission } from '@/types/analysis'
import { API_BASE_URL } from '@/services/api'

// Default URL scan limit (can be increased by user)
const DEFAULT_URLSCAN_LIMIT = 10

/**
 * Composable for managing email analysis state and interactions.
 * 
 * Handles file selection, drag-and-drop, API submission, and
 * managing the analysis lifecycle (loading, error, success).
 * 
 * @returns Object containing reactive state and methods for analysis.
 */
export function useAnalysisState() {
  const store = useAnalysisStore()
  const fileInputRef = ref<HTMLInputElement | null>(null)
  const isDragActive = ref(false)

  // Track current urlscan limit for "scan more" feature
  const currentUrlscanLimit = ref(DEFAULT_URLSCAN_LIMIT)
  const scanningMoreUrls = ref(false)

  // Computed properties mapping to store state
  const selectedFile = computed(() => store.selectedFile)
  const analysisResult = computed(() => store.analysisResult)
  const loading = computed(() => store.loading)
  const errorMessage = computed(() => store.errorMessage)

  // Show elapsed time (timer runs in store, persists across view switches)
  const elapsedSeconds = computed(() => store.elapsedSeconds)

  const isSubmitDisabled = computed(() => store.loading || !store.selectedFile)
  const selectedFileLabel = computed(() => store.selectedFileLabel)

  const prettyJson = (value: unknown) => JSON.stringify(value, null, 2)

  /**
   * Handle file selection from input element.
   * @param event - Change event from input[type="file"]
   */
  const onFileChange = (event: Event) => {
    const target = event.target as HTMLInputElement
    const [file] = target.files ?? []
    store.setSelectedFile(file ?? null)
  }

  const triggerFileDialog = () => fileInputRef.value?.click()

  const onDragOver = (event: DragEvent) => {
    event.preventDefault()
    if (!store.loading) {
      isDragActive.value = true
    }
  }

  const onDragLeave = (event: DragEvent) => {
    if (event.currentTarget === event.target) {
      isDragActive.value = false
    }
  }

  const onDrop = (event: DragEvent) => {
    event.preventDefault()
    if (store.loading) {
      isDragActive.value = false
      return
    }
    const [file] = event.dataTransfer?.files ?? []
    store.setSelectedFile(file ?? null)
    isDragActive.value = false
  }

  const clearFile = () => {
    store.setSelectedFile(null)
    if (fileInputRef.value) {
      fileInputRef.value.value = ''
    }
  }

  /**
   * Submit selected file for analysis.
   * Validates file type and size before uploading.
   */
  const submit = async () => {
    if (!store.selectedFile) {
      store.setError('Please choose an email file before analyzing.')
      return
    }

    const fileName = store.selectedFile.name.toLowerCase()
    if (!fileName.endsWith('.eml')) {
      store.setError('Only .eml files are allowed.')
      return
    }

    if (store.selectedFile.size > 10 * 1024 * 1024) {
      store.setError('File too large. Maximum size is 10MB.')
      return
    }

    const params = new URLSearchParams({
      run_all_detection_rules: '1',
      run_all_insights: '1',
      include_workflow_rules: '0',
      request_attack_score: '1',
      perform_threat_enrichment: '1',
      max_urlscan_submissions: currentUrlscanLimit.value.toString(),
      urlscan_visibility: 'unlisted',
    })

    const formData = new FormData()
    formData.append('file', store.selectedFile)

    // setLoading(true) now starts the timer automatically in the store
    store.setLoading(true)

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/analysis/email?${params.toString()}`, {
        method: 'POST',
        body: formData,
        credentials: 'include',
      })
      if (!response.ok) {
        const details = await response.text()
        throw new Error(`Backend responded with ${response.status}: ${details}`)
      }
      const result = (await response.json()) as CombinedAnalysisResult
      // setAnalysisResult stops the timer automatically
      store.setAnalysisResult(result)

      // Fetch AI recommendation after analysis completes
      store.fetchAIRecommendation()
    } catch (error) {
      console.error(error)
      // setError stops the timer automatically
      store.setError(
        error instanceof Error ? error.message : 'Unable to analyze the email. Please try again later.'
      )
    }
  }

  // AI Recommendation
  const aiRecommendation = computed(() => store.aiRecommendation)
  const aiRecommendationLoading = computed(() => store.aiRecommendationLoading)

  // Check if there are more URLs that weren't scanned (truncated message in urlscan results)
  const hasMoreUrlsToScan = computed(() => {
    const urlscan = store.analysisResult?.threat_intel?.urlscan
    if (!urlscan || !Array.isArray(urlscan)) return false
    // Check if there's a truncation message in the results
    return urlscan.some((s: UrlscanSubmission) => s.error?.includes('truncated'))
  })

  // Get count of URLs that were skipped
  const skippedUrlCount = computed(() => {
    const urlscan = store.analysisResult?.threat_intel?.urlscan
    if (!urlscan || !Array.isArray(urlscan)) return 0
    const truncatedMsg = urlscan.find((s: UrlscanSubmission) => s.error?.includes('truncated'))
    if (truncatedMsg?.error) {
      const match = truncatedMsg.error.match(/skipped (\d+)/)
      return match?.[1] ? parseInt(match[1], 10) : 0
    }
    return 0
  })

  // Helper function to run analysis with a specific URL scan limit
  const runAnalysisWithLimit = async (urlLimit: number): Promise<void> => {
    if (!store.selectedFile) return

    const params = new URLSearchParams({
      run_all_detection_rules: '1',
      run_all_insights: '1',
      include_workflow_rules: '0',
      request_attack_score: '1',
      perform_threat_enrichment: '1',
      max_urlscan_submissions: urlLimit.toString(),
      urlscan_visibility: 'unlisted',
    })

    const formData = new FormData()
    formData.append('file', store.selectedFile)

    const response = await fetch(`${API_BASE_URL}/api/v1/analysis/email?${params.toString()}`, {
      method: 'POST',
      body: formData,
      credentials: 'include',
    })
    if (!response.ok) {
      const details = await response.text()
      throw new Error(`Backend responded with ${response.status}: ${details}`)
    }
    const result = (await response.json()) as CombinedAnalysisResult
    store.setAnalysisResult(result)
  }

  // Re-analyze with more URLs
  const scanMoreUrls = async (additionalCount: number = 20) => {
    if (!store.selectedFile || scanningMoreUrls.value) return

    scanningMoreUrls.value = true

    // Increase the limit
    currentUrlscanLimit.value += additionalCount

    try {
      await runAnalysisWithLimit(currentUrlscanLimit.value)
    } catch (error) {
      console.error('Failed to scan more URLs:', error)
      store.setError(
        error instanceof Error ? error.message : 'Failed to scan more URLs. Please try again.'
      )
    } finally {
      scanningMoreUrls.value = false
    }
  }

  // Scan all remaining URLs (set limit to max 50)
  const scanAllUrls = async () => {
    if (!store.selectedFile || scanningMoreUrls.value) return

    scanningMoreUrls.value = true
    currentUrlscanLimit.value = 50 // Max allowed by backend

    try {
      await runAnalysisWithLimit(50)
    } catch (error) {
      console.error('Failed to scan all URLs:', error)
      store.setError(
        error instanceof Error ? error.message : 'Failed to scan all URLs. Please try again.'
      )
    } finally {
      scanningMoreUrls.value = false
    }
  }

  return {
    analysisResult,
    errorMessage,
    fileInputRef,
    isDragActive,
    isSubmitDisabled,
    loading,
    onDragLeave,
    onDragOver,
    onDrop,
    onFileChange,
    prettyJson,
    elapsedSeconds,
    selectedFile,
    selectedFileLabel,
    clearFile,
    submit,
    triggerFileDialog,
    aiRecommendation,
    aiRecommendationLoading,
    // URL scanning features
    hasMoreUrlsToScan,
    skippedUrlCount,
    scanMoreUrls,
    scanAllUrls,
    scanningMoreUrls,
    currentUrlscanLimit,
  }
}
