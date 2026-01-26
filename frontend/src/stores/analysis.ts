import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { CombinedAnalysisResult, LinkAnalysisResult, FileAnalysisResult } from '@/types/analysis'
import { API_BASE_URL } from '@/services/api'

export interface AIRecommendation {
    recommendation: string
    risk_level: 'low' | 'medium' | 'high' | 'critical'
    actions: string[]
}

// Analysis type for tracking which analysis is active
export type AnalysisType = 'email' | 'link' | 'file' | null

// Re-export types for backwards compatibility
export type { LinkAnalysisResult, FileAnalysisResult } from '@/types/analysis'

export const useAnalysisStore = defineStore('analysis', () => {
    const selectedFile = ref<File | null>(null)
    const analysisResult = ref<CombinedAnalysisResult | null>(null)
    const loading = ref(false)
    const errorMessage = ref<string | null>(null)
    const progressPercent = ref(0)
    const elapsedSeconds = ref(0)

    // Timer handle stored in the store (persists across component switches)
    let timerHandle: number | null = null

    // AI Recommendation state
    const aiRecommendation = ref<AIRecommendation | null>(null)
    const aiRecommendationLoading = ref(false)

    // Track which type of analysis is active
    const activeAnalysisType = ref<AnalysisType>(null)

    // Link and File analysis results
    const linkAnalysisResult = ref<LinkAnalysisResult | null>(null)
    const fileAnalysisResult = ref<FileAnalysisResult | null>(null)

    // Computed: check if any analysis is available
    const hasAnyAnalysis = computed(() =>
        !!analysisResult.value || !!linkAnalysisResult.value || !!fileAnalysisResult.value
    )

    const selectedFileLabel = computed(() => selectedFile.value?.name ?? 'No file selected')

    // Timer management functions
    function startTimer() {
        if (timerHandle === null) {
            timerHandle = window.setInterval(() => {
                elapsedSeconds.value += 1
            }, 1000)
        }
    }

    function stopTimer() {
        if (timerHandle !== null) {
            window.clearInterval(timerHandle)
            timerHandle = null
        }
    }

    function resetTimer() {
        stopTimer()
        elapsedSeconds.value = 0
    }

    function reset() {
        selectedFile.value = null
        analysisResult.value = null
        loading.value = false
        errorMessage.value = null
        progressPercent.value = 0
        resetTimer()
        aiRecommendation.value = null
        aiRecommendationLoading.value = false
    }

    // Reset all analysis results (used on logout)
    function resetAll() {
        reset()
        linkAnalysisResult.value = null
        fileAnalysisResult.value = null
        activeAnalysisType.value = null
    }

    function setAnalysisResult(result: CombinedAnalysisResult) {
        analysisResult.value = result
        activeAnalysisType.value = 'email'
        loading.value = false
        errorMessage.value = null
        stopTimer()
    }

    function setLinkAnalysisResult(result: LinkAnalysisResult | null) {
        linkAnalysisResult.value = result
        activeAnalysisType.value = result ? 'link' : null
    }

    function setFileAnalysisResult(result: FileAnalysisResult | null) {
        fileAnalysisResult.value = result
        activeAnalysisType.value = result ? 'file' : null
    }

    function setLoading(isLoading: boolean) {
        loading.value = isLoading
        if (isLoading) {
            errorMessage.value = null
            resetTimer()
            startTimer()
        } else {
            stopTimer()
        }
    }

    function setError(message: string) {
        errorMessage.value = message
        loading.value = false
        stopTimer()
    }

    function setSelectedFile(file: File | null) {
        selectedFile.value = file
        if (file) {
            errorMessage.value = null
        }
    }

    async function fetchAIRecommendation() {
        if (!analysisResult.value) return

        aiRecommendationLoading.value = true

        try {
            const result = analysisResult.value
            const attackScore = typeof result.sublime?.attack_score?.score === 'number'
                ? result.sublime.attack_score.score
                : undefined
            const verdict = typeof result.sublime?.attack_score?.verdict === 'string'
                ? result.sublime.attack_score.verdict
                : undefined
            const ruleCount = result.sublime?.rule_hits?.length || 0
            const insightCount = result.sublime?.insight_hits?.length || 0

            // Get VT stats - using proper VTData type
            let vtMalicious = 0
            let vtSuspicious = 0
            if (result.threat_intel?.virustotal?.length) {
                for (const vt of result.threat_intel.virustotal) {
                    const stats = vt.data?.attributes?.last_analysis_stats
                    if (stats) {
                        vtMalicious += stats.malicious || 0
                        vtSuspicious += stats.suspicious || 0
                    }
                }
            }

            // Get email details - using proper ParsedEmail/EmailAddress types
            const parsed = result.parsed_email
            const senderDomain = parsed?.from?.domain || parsed?.sender_domain || null
            const subject = parsed?.subject || null
            const attachments = parsed?.attachments || []
            const hasAttachments = attachments.length > 0
            const attachmentTypes = attachments.map(a => {
                const ext = a.filename?.split('.').pop()?.toLowerCase()
                return ext || a.content_type
            }).filter(Boolean)

            // Extract IPQS data (aggregated)
            let ipqsMaxFraudScore: number | null = null
            const ipqsFlags: string[] = []
            if (result.threat_intel?.ipqs?.length) {
                for (const ipqs of result.threat_intel.ipqs) {
                    if (ipqs.fraud_score != null && (ipqsMaxFraudScore === null || ipqs.fraud_score > ipqsMaxFraudScore)) {
                        ipqsMaxFraudScore = ipqs.fraud_score
                    }
                    if (ipqs.is_vpn) ipqsFlags.push('vpn')
                    if (ipqs.is_tor) ipqsFlags.push('tor')
                    if (ipqs.is_proxy) ipqsFlags.push('proxy')
                    if (ipqs.is_bot) ipqsFlags.push('bot')
                    if (ipqs.recent_abuse) ipqsFlags.push('recent_abuse')
                }
            }
            const uniqueIpqsFlags = [...new Set(ipqsFlags)]

            // Extract URLScan data (aggregated - prioritizing worst verdict AND counting)
            let urlscanVerdict: string | null = null
            let urlscanMaliciousCount = 0
            let urlscanSuspiciousCount = 0
            const urlscanTags: string[] = []

            if (result.threat_intel?.urlscan?.length) {
                for (const us of result.threat_intel.urlscan) {
                    const currentV = us.verdict?.toLowerCase()

                    if (currentV === 'malicious') {
                        urlscanMaliciousCount++
                        urlscanVerdict = 'malicious'
                    } else if (currentV === 'suspicious') {
                        urlscanSuspiciousCount++
                        if (urlscanVerdict !== 'malicious') {
                            urlscanVerdict = 'suspicious'
                        }
                    } else if (currentV && !urlscanVerdict) {
                        urlscanVerdict = currentV
                    }

                    if (us.tags) urlscanTags.push(...us.tags)
                }
            }
            const uniqueUrlscanTags = [...new Set(urlscanTags)]

            // Extract Hybrid Analysis data (aggregated - prioritizing worst verdict AND counting)
            let haMaxThreatScore: number | null = null
            let haVerdict: string | null = null
            let haMaliciousCount = 0
            let haSuspiciousCount = 0

            if (result.threat_intel?.hybrid_analysis?.length) {
                for (const ha of result.threat_intel.hybrid_analysis) {
                    if (ha.threat_score != null && (haMaxThreatScore === null || ha.threat_score > haMaxThreatScore)) {
                        haMaxThreatScore = ha.threat_score
                    }

                    const currentV = ha.verdict?.toLowerCase()
                    if (currentV === 'malicious') {
                        haMaliciousCount++
                        haVerdict = 'malicious'
                    } else if (currentV === 'suspicious') {
                        haSuspiciousCount++
                        if (haVerdict !== 'malicious') {
                            haVerdict = 'suspicious'
                        }
                    } else if (currentV && !haVerdict) {
                        haVerdict = currentV
                    }
                }
            }

            const response = await fetch(`${API_BASE_URL}/api/v1/ai/recommendation`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({
                    attack_score: attackScore,
                    verdict: verdict,
                    rule_count: ruleCount,
                    insight_count: insightCount,
                    vt_malicious: vtMalicious,
                    vt_suspicious: vtSuspicious,
                    sender_domain: senderDomain,
                    subject: subject,
                    has_attachments: hasAttachments,
                    attachment_types: attachmentTypes,
                    // New threat intel fields
                    ipqs_max_fraud_score: ipqsMaxFraudScore,
                    ipqs_flags: uniqueIpqsFlags.length > 0 ? uniqueIpqsFlags : null,
                    urlscan_verdict: urlscanVerdict,
                    urlscan_tags: uniqueUrlscanTags.length > 0 ? uniqueUrlscanTags : null,
                    urlscan_malicious_count: urlscanMaliciousCount,
                    urlscan_suspicious_count: urlscanSuspiciousCount,
                    ha_max_threat_score: haMaxThreatScore,
                    ha_verdict: haVerdict,
                    ha_malicious_count: haMaliciousCount,
                    ha_suspicious_count: haSuspiciousCount
                })
            })
            if (response.ok) {
                aiRecommendation.value = await response.json()
            }
        } catch (error) {
            console.error('Failed to fetch AI recommendation:', error)
        } finally {
            aiRecommendationLoading.value = false
        }
    }

    return {
        selectedFile,
        analysisResult,
        linkAnalysisResult,
        fileAnalysisResult,
        activeAnalysisType,
        hasAnyAnalysis,
        loading,
        errorMessage,
        progressPercent,
        elapsedSeconds,
        selectedFileLabel,
        aiRecommendation,
        aiRecommendationLoading,
        reset,
        resetAll,
        setAnalysisResult,
        setLinkAnalysisResult,
        setFileAnalysisResult,
        setLoading,
        setError,
        setSelectedFile,
        fetchAIRecommendation
    }
})
