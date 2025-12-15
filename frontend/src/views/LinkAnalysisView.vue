<script setup lang="ts">
import { ref, computed, onUnmounted, watch } from 'vue'
import {
    Link,
    Search,
    RefreshCw,
    AlertTriangle,
    ArrowRight,
    ExternalLink,
    CheckCircle,
    XCircle,
    AlertOctagon,
    Globe,
    Shield,
    Eye,
    Clock,
    Tag,
    FileText,
    ChevronDown,
    ChevronUp,
    ChevronRight,
    Copy,
    Check,
    Info,
    Fingerprint,
    Building,
    Bug,
    Activity,
    KeyRound,
    ShieldCheck,
    Loader2
} from 'lucide-vue-next'
import { isPlaceholderScreenshot, getLiveshotUrl, isVerdictPending } from '@/utils/screenshotUtils'
import { useAnalysisStore } from '@/stores/analysis'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

// Analysis store for AI chat integration
const analysisStore = useAnalysisStore()

const urlInput = ref('')
const loading = ref(false)
const errorMessage = ref('')
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const analysisResult = ref<any>(null)
const copiedField = ref('')
const screenshotLoading = ref(false)
const screenshotBroken = ref(false)
const screenshotRetryCount = ref(0)
const MAX_AUTO_RETRIES = 3
const SCREENSHOT_TIMEOUT_MS = 15000
let screenshotTimeout: ReturnType<typeof setTimeout> | null = null

// URLscan polling state
const autoRefreshInterval = ref<number | null>(null)
const autoRefreshStartTime = ref<number | null>(null)
const AUTO_REFRESH_INTERVAL_MS = 5000 // Poll every 5 seconds (more aggressive for single link)
const AUTO_REFRESH_MAX_DURATION_MS = 120000 // Stop after 2 minutes

const expandedSections = ref<Record<string, boolean>>({
    urlscan: true,
    virustotal: true,
    details: false,
    raw: false
})

// Get the screenshot URL - only use stored screenshot from URLscan result
// Don't use liveshot fallback as it often returns placeholder images for suspicious sites
const screenshotUrl = computed(() => {
    const urlscan = analysisResult.value?.urlscan
    if (!urlscan) return null

    const storedUrl = urlscan.screenshot_url

    // Only use stored screenshot if it exists and isn't a placeholder
    if (storedUrl && !isPlaceholderScreenshot(storedUrl)) {
        // Add cache buster for retries
        if (screenshotRetryCount.value > 0) {
            const separator = storedUrl.includes('?') ? '&' : '?'
            return `${storedUrl}${separator}_cb=${screenshotRetryCount.value}`
        }
        return storedUrl
    }

    // Use liveshot as fallback if no stored screenshot
    return getLiveshotUrl(analysisResult.value?.url || analysisResult.value?.urlscan?.url)
})

function startScreenshotTimeout() {
    if (screenshotTimeout) clearTimeout(screenshotTimeout)

    screenshotTimeout = setTimeout(() => {
        if (screenshotLoading.value) {
            if (screenshotRetryCount.value < MAX_AUTO_RETRIES) {
                console.log(`Screenshot timeout, auto-retrying (attempt ${screenshotRetryCount.value + 1})`)
                screenshotRetryCount.value++
                screenshotLoading.value = false
                setTimeout(() => { screenshotLoading.value = true }, 100)
            } else {
                console.log('Screenshot timeout, max retries reached')
                screenshotLoading.value = false
                screenshotBroken.value = true
            }
        }
    }, SCREENSHOT_TIMEOUT_MS)
}

function onScreenshotLoad() {
    if (screenshotTimeout) clearTimeout(screenshotTimeout)
    screenshotLoading.value = false
    screenshotBroken.value = false
}

function onScreenshotError() {
    if (screenshotTimeout) clearTimeout(screenshotTimeout)

    if (screenshotRetryCount.value < MAX_AUTO_RETRIES) {
        console.log(`Screenshot error, auto-retrying (attempt ${screenshotRetryCount.value + 1})`)
        screenshotRetryCount.value++
        screenshotLoading.value = false
        setTimeout(() => { screenshotLoading.value = true }, 500)
    } else {
        screenshotLoading.value = false
        screenshotBroken.value = true
    }
}

function retryScreenshot() {
    screenshotRetryCount.value = 0
    screenshotBroken.value = false
    screenshotLoading.value = true
    startScreenshotTimeout()
}

// Polling logic for URLscan results
const refreshUrlscan = async (scanId: string) => {
    if (!scanId) return

    try {
        console.log(`Refreshing URLscan: ${scanId}`)
        const resp = await fetch(`${API_BASE_URL}/api/v1/analysis/urlscan/${encodeURIComponent(scanId)}`)
        if (!resp.ok) return

        const updated = await resp.json()
        console.log('URLscan refresh result:', updated)

        if (analysisResult.value) {
            // Update the urlscan part of the result
            analysisResult.value = {
                ...analysisResult.value,
                urlscan: {
                    ...analysisResult.value.urlscan,
                    ...updated,
                    // Preserve initial URL if missing in update
                    url: updated.url || analysisResult.value.urlscan?.url,
                    // Preserve Sublime ML data (refresh only returns URLscan data)
                    ml_link: updated.ml_link || analysisResult.value.urlscan?.ml_link
                }
            }
            // Update store
            analysisStore.setLinkAnalysisResult(analysisResult.value)
        }
    } catch (error) {
        console.error('URLscan refresh error:', error)
    }
}

const stopAutoRefresh = () => {
    if (autoRefreshInterval.value) {
        window.clearInterval(autoRefreshInterval.value)
        autoRefreshInterval.value = null
        autoRefreshStartTime.value = null
        console.log('URLscan polling stopped')
    }
}

const startAutoRefresh = (scanId: string) => {
    if (autoRefreshInterval.value) return // Already running

    autoRefreshStartTime.value = Date.now()
    console.log('Starting URLscan auto-refresh for:', scanId)

    // Initial check immediately
    refreshUrlscan(scanId)

    autoRefreshInterval.value = window.setInterval(async () => {
        // Check timeout
        const elapsed = Date.now() - (autoRefreshStartTime.value ?? 0)
        if (elapsed > AUTO_REFRESH_MAX_DURATION_MS) {
            stopAutoRefresh()
            return
        }

        // Check if verdict is still pending
        const urlscan = analysisResult.value?.urlscan
        if (!urlscan || !urlscan.scan_id) {
            stopAutoRefresh()
            return
        }

        // Check verification status
        if (!isVerdictPending(urlscan.verdict)) {
            console.log('Scan completed, stopping polling')
            stopAutoRefresh()
            return
        }

        // Optimization: Stop polling if we already have a High/Critical risk verdict
        // No need to wait for Urlscan screenshot if we already know it's malware
        const currentRisk = overallRisk.value?.level
        if (currentRisk === 'high' || currentRisk === 'critical') {
            console.log('High/Critical risk detected, stopping unnecessary polling')
            stopAutoRefresh()
            return
        }

        // Perform refresh
        await refreshUrlscan(scanId)

    }, AUTO_REFRESH_INTERVAL_MS)
}

// Timer for elapsed seconds
const elapsedSeconds = ref(0)
let timerHandle: number | null = null

function startTimer() {
    elapsedSeconds.value = 0
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

onUnmounted(() => {
    stopTimer()
    stopAutoRefresh()
    if (screenshotTimeout) clearTimeout(screenshotTimeout)
    // Clear link analysis from store when leaving
    analysisStore.setLinkAnalysisResult(null)
})

const submitLink = async () => {
    if (!urlInput.value) return

    loading.value = true
    errorMessage.value = ''
    analysisResult.value = null
    screenshotBroken.value = false
    screenshotLoading.value = false
    screenshotRetryCount.value = 0
    stopAutoRefresh() // Ensure clean slate
    startTimer()

    try {
        const response = await fetch(`${API_BASE_URL}/api/v1/analysis/link`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: urlInput.value }),
        })

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}))
            const errorMsg = typeof errorData.detail === 'string'
                ? errorData.detail
                : errorData.detail?.message || errorData.message || `Backend responded with ${response.status}`
            throw new Error(errorMsg)
        }

        analysisResult.value = await response.json()

        // Start polling if verdict is pending
        const urlscan = analysisResult.value?.urlscan
        if (urlscan?.scan_id && (isVerdictPending(urlscan.verdict) || urlscan.verdict === 'pending')) {
            startAutoRefresh(urlscan.scan_id)
        }

        // Sync to store for AI chat integration
        analysisStore.setLinkAnalysisResult(analysisResult.value)
    } catch (error) {
        console.error('Link analysis failed:', error)
        errorMessage.value = error instanceof Error ? error.message : 'Failed to analyze link. Please try again.'
    } finally {
        loading.value = false
        stopTimer()
    }
}

// Overall risk assessment
const overallRisk = computed(() => {
    if (!analysisResult.value) return null

    const ml = analysisResult.value?.urlscan?.ml_link
    const vtData = analysisResult.value?.virustotal?.[0]?.data?.attributes?.last_analysis_stats
    const analyzedUrl = analysisResult.value?.urlscan?.url || ''

    let riskScore = 0
    const riskFactors: string[] = []

    // Check if URL is a download link (executable/archive file extension)
    const downloadExtensions = [
        // Executables & Installers
        '.exe', '.scr', '.bat', '.cmd', '.msi', '.dll', '.com', '.cpl', '.reg',
        // Archives
        '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.cab',
        // Scripts
        '.ps1', '.vbs', '.js', '.hta', '.wsf', '.jse', '.vbe', '.sh', '.bin', '.py',
        // Mobile & Java
        '.dmg', '.apk', '.jar',
        // Office Macros
        '.docm', '.xlsm', '.pptm'
    ]
    const urlPath = analyzedUrl.toLowerCase().split('?')[0]
    const isExtensionDownload = downloadExtensions.some(ext => urlPath.endsWith(ext))

    // Check if API detected download via Content-Type/Content-Disposition
    const isApiDetectedDownload = analysisResult.value?.is_download === true

    // Combined check
    const isDownloadLink = isExtensionDownload || isApiDetectedDownload

    // Check if URL uses raw IP address instead of domain
    const ipPattern = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/
    const isRawIP = ipPattern.test(analyzedUrl)

    // Download link is inherently more risky
    if (isDownloadLink) {
        riskScore += 25
        riskFactors.push('Direct file download link')
    }

    // Raw IP URLs are suspicious
    if (isRawIP) {
        riskScore += 10
        riskFactors.push('Uses raw IP address (no domain)')
    }

    // ML Score contribution
    if (ml?.score) {
        riskScore += ml.score * 50
        if (ml.score >= 0.8) riskFactors.push('High ML malicious score')
        else if (ml.score >= 0.5) riskFactors.push('Moderate ML suspicious score')
    }

    // VirusTotal contribution - increased weight for any malicious detection
    if (vtData) {
        const malicious = vtData.malicious || 0
        const suspicious = vtData.suspicious || 0
        if (malicious > 0) {
            // Base 15 points for any detection, plus 10 per additional
            riskScore += 15 + Math.min(malicious * 10, 45)
            riskFactors.push(`${malicious} VT malicious detections`)
        }
        if (suspicious > 0) {
            riskScore += Math.min(suspicious * 3, 15)
            riskFactors.push(`${suspicious} VT suspicious detections`)
        }
    }

    // Tags contribution
    const tags = analysisResult.value?.urlscan?.tags || []
    if (tags.includes('phishing')) {
        riskScore += 20
        riskFactors.push('Tagged as phishing')
    }
    if (tags.includes('malware')) {
        riskScore += 25
        riskFactors.push('Tagged as malware')
    }

    // Determine verdict using industry labels
    if (riskScore >= 70) return { level: 'critical', label: 'Malicious', color: 'text-red-500', bgColor: 'bg-red-500/10', borderColor: 'border-red-500/30', icon: XCircle, factors: riskFactors }
    if (riskScore >= 40) return { level: 'high', label: 'Suspicious', color: 'text-orange-500', bgColor: 'bg-orange-500/10', borderColor: 'border-orange-500/30', icon: AlertOctagon, factors: riskFactors }
    if (riskScore >= 20) return { level: 'medium', label: 'Low Risk', color: 'text-yellow-500', bgColor: 'bg-yellow-500/10', borderColor: 'border-yellow-500/30', icon: AlertTriangle, factors: riskFactors }
    return { level: 'low', label: 'Clean', color: 'text-emerald-500', bgColor: 'bg-emerald-500/10', borderColor: 'border-emerald-500/30', icon: CheckCircle, factors: riskFactors.length ? riskFactors : ['No significant threats detected'] }
})

// Raw ML link data for detailed display
const sublimeMlData = computed(() => {
    return analysisResult.value?.urlscan?.ml_link || null
})

const sublimeVerdict = computed(() => {
    const ml = analysisResult.value?.urlscan?.ml_link
    // No ml_link at all means API not configured or failed
    if (!ml) return null

    // Handle IP skip case - show message instead of "Unknown"
    if (ml.skip_reason === 'ip_address') {
        return {
            label: 'Not Supported',
            color: 'text-muted-foreground',
            bgColor: 'bg-muted/50',
            icon: Info,
            description: 'ML analysis not available for IP-based URLs',
            score: null,
            containsLogin: null,
            containsCaptcha: null,
            isSkipped: true
        }
    }

    const label = ml.label // "benign", "suspicious", "malicious"
    const score = ml.score
    const containsLogin = ml.contains_login
    const containsCaptcha = ml.contains_captcha

    // Determine display based on label (disposition)
    if (label === 'malicious') {
        return {
            label: 'Malicious',
            color: 'text-red-500',
            bgColor: 'bg-red-500/10',
            icon: XCircle,
            description: 'Credential phishing detected',
            score,
            containsLogin,
            containsCaptcha
        }
    }
    if (label === 'suspicious') {
        return {
            label: 'Suspicious',
            color: 'text-yellow-500',
            bgColor: 'bg-yellow-500/10',
            icon: AlertOctagon,
            description: 'Potential phishing indicators found',
            score,
            containsLogin,
            containsCaptcha
        }
    }
    if (label === 'benign') {
        return {
            label: 'Benign',
            color: 'text-emerald-500',
            bgColor: 'bg-emerald-500/10',
            icon: CheckCircle,
            description: 'No credential phishing detected',
            score,
            containsLogin,
            containsCaptcha
        }
    }
    // Unknown or null label
    return {
        label: 'Unknown',
        color: 'text-muted-foreground',
        bgColor: 'bg-muted/50',
        icon: Info,
        description: 'Analysis incomplete',
        score: null,
        containsLogin,
        containsCaptcha
    }
})

const vtStats = computed(() => {
    const vt = analysisResult.value?.virustotal
    if (!vt || vt.length === 0) return null
    const data = vt[0].data?.attributes?.last_analysis_stats
    if (!data) return null
    return data
})

const vtDetails = computed(() => {
    const vt = analysisResult.value?.virustotal?.[0]?.data?.attributes
    if (!vt) return null
    return {
        categories: vt.categories || {},
        reputation: vt.reputation || 0,
        lastAnalysisDate: vt.last_analysis_date ? new Date(vt.last_analysis_date * 1000).toLocaleString() : null,
        lastModificationDate: vt.last_modification_date ? new Date(vt.last_modification_date * 1000).toLocaleString() : null,
        registrar: vt.registrar,
        creationDate: vt.creation_date ? new Date(vt.creation_date * 1000).toLocaleDateString() : null,
        lastDnsRecords: vt.last_dns_records || [],
        totalVotes: vt.total_votes || { harmless: 0, malicious: 0 }
    }
})

const urlscanDetails = computed(() => {
    const urlscan = analysisResult.value?.urlscan
    if (!urlscan) return null
    return {
        url: urlscan.url,
        scanId: urlscan.scan_id,
        visibility: urlscan.visibility,
        verdict: urlscan.verdict,
        tags: urlscan.tags || [],
        screenshotUrl: urlscan.screenshot_url,
        resultUrl: urlscan.result_url,
        mlScore: urlscan.ml_link?.score,
        mlCategories: urlscan.ml_link?.categories || []
    }
})

// Separated raw data for JSON display
const separatedRawData = computed(() => {
    if (!analysisResult.value) return null

    const urlscan = analysisResult.value.urlscan
    const sublimeMl = urlscan?.ml_link || null

    // Create URLscan data without ml_link
    let urlscanWithoutMl = null
    if (urlscan) {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        const { ml_link, ...rest } = urlscan
        urlscanWithoutMl = rest
    }

    return {
        sublime_ml: sublimeMl,
        urlscan: urlscanWithoutMl,
        virustotal: analysisResult.value.virustotal || null
    }
})

function toggleSection(section: string) {
    expandedSections.value[section] = !expandedSections.value[section]
}

// Helper to check if a string is an IP address
function isIpAddress(host: string): boolean {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
    const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
    return ipv4.test(host) || ipv6.test(host)
}

// Reactive VT URL - computed when URL changes
const vtUrlRef = ref<string>('')

// Helper to compute base64url ID of URL for VirusTotal (without padding)
function computeVtUrlBase64(url: string): string {
    return btoa(url)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')
}

// Compute VT URL using base64url ID
// Shows existing results if available, triggers analysis if not found
function updateVtUrl() {
    const url = urlInput.value
    if (!url) {
        vtUrlRef.value = ''
        return
    }

    try {
        // Ensure URL has protocol
        const fullUrl = url.startsWith('http') ? url : `https://${url}`
        const base64Id = computeVtUrlBase64(fullUrl)
        // /gui/url/{base64} shows report or triggers scan
        vtUrlRef.value = `https://www.virustotal.com/gui/url/${base64Id}`
    } catch {
        // Fallback to search if encoding fails
        vtUrlRef.value = `https://www.virustotal.com/gui/search/${encodeURIComponent(url)}`
    }
}

// Helper to get VirusTotal URL (reads from reactive ref)
function getVtUrl(): string | undefined {
    return vtUrlRef.value || undefined
}

// Watch urlInput and analysisResult to update VT URL
watch([urlInput, analysisResult], () => {
    updateVtUrl()
}, { immediate: true })

// Helper to get URLscan.io result URL
function getUrlscanUrl(): string | undefined {
    const urlscan = analysisResult.value?.urlscan

    // If screenshot is broken (scan failed), go to search instead of error result page
    const scanFailed = screenshotBroken.value || !urlscan?.screenshot_url

    // If urlscan has result_url AND scan didn't fail, use it
    if (urlscan?.result_url && !scanFailed) {
        return urlscan.result_url
    }

    // If urlscan has scan_id AND scan didn't fail, construct result URL
    if (urlscan?.scan_id && !scanFailed) {
        return `https://urlscan.io/result/${urlscan.scan_id}/`
    }

    // Fallback: search by domain from urlscan.url or urlInput
    const urlToSearch = urlscan?.url || urlInput.value
    if (urlToSearch) {
        try {
            const urlObj = new URL(urlToSearch.startsWith('http') ? urlToSearch : `https://${urlToSearch}`)
            // Use page.domain: format which is the correct URLscan.io search syntax
            return `https://urlscan.io/search/#page.domain:${urlObj.hostname}`
        } catch {
            return `https://urlscan.io/search/#page.url:${encodeURIComponent(urlToSearch)}`
        }
    }

    return undefined
}

async function copyToClipboard(text: string, field: string) {
    try {
        await navigator.clipboard.writeText(text)
        copiedField.value = field
        setTimeout(() => copiedField.value = '', 2000)
    } catch (err) {
        console.error('Failed to copy:', err)
    }
}

function formatUrl(url: string): { protocol: string; domain: string; path: string } {
    try {
        const urlObj = new URL(url)
        return {
            protocol: urlObj.protocol.replace(':', ''),
            domain: urlObj.hostname,
            path: urlObj.pathname + urlObj.search
        }
    } catch {
        return { protocol: '', domain: url, path: '' }
    }
}

// JSON Tree View state
const jsonExpandedNodes = ref<Set<string>>(new Set())

// Reset JSON tree state when new analysis result comes in
watch(() => analysisResult.value, () => {
    jsonExpandedNodes.value.clear()
    expandedSections.value.raw = false
})

function toggleJsonNode(path: string) {
    if (jsonExpandedNodes.value.has(path)) {
        jsonExpandedNodes.value.delete(path)
    } else {
        jsonExpandedNodes.value.add(path)
    }
}

function isJsonNodeExpanded(path: string): boolean {
    return jsonExpandedNodes.value.has(path)
}

function getItemLabel(value: unknown): string {
    if (Array.isArray(value)) {
        return `[] ${value.length} items`
    }
    if (typeof value === 'object' && value !== null) {
        return `{} ${Object.keys(value).length} items`
    }
    return String(value)
}

function prettyJson(value: unknown): string {
    return JSON.stringify(value, null, 2)
}

</script>

<template>
    <main class="min-h-screen bg-background text-foreground font-sans selection:bg-primary/30 pb-20">
        <!-- Hero / Header Section -->
        <section
            class="relative py-16 px-4 sm:px-6 lg:px-8 flex flex-col items-center justify-center text-center overflow-hidden">
            <div class="absolute inset-0 bg-primary/5 blur-[100px] rounded-full pointer-events-none"></div>

            <div class="relative z-10 max-w-3xl mx-auto space-y-6 animate-fade-in">
                <div
                    class="inline-flex items-center justify-center p-3 bg-primary/10 rounded-2xl mb-4 ring-1 ring-primary/20 shadow-lg shadow-primary/10">
                    <Link class="w-10 h-10 text-primary" />
                </div>

                <h1
                    class="text-5xl md:text-6xl font-bold tracking-tight text-gray-900 dark:bg-gradient-to-b dark:from-white dark:to-white/60 dark:bg-clip-text dark:text-transparent drop-shadow-sm">
                    Link Analysis
                </h1>

                <p class="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
                    Inspect suspicious URLs with <span class="text-primary font-medium">VirusTotal</span>, <span
                        class="text-primary font-medium">urlscan.io</span>, and <span
                        class="text-primary font-medium">Sublime Security</span>.
                </p>
            </div>
        </section>

        <!-- Input Section -->
        <section class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 mb-16 relative z-10">
            <div
                class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-xl rounded-3xl p-8 md:p-12 transition-all duration-500 hover:shadow-primary/5">

                <div class="flex flex-col items-center gap-8">
                    <!-- Status Indicator -->
                    <div class="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-sm font-medium transition-colors duration-300"
                        :class="loading ? 'bg-primary/20 text-primary animate-pulse' : 'bg-secondary text-secondary-foreground'">
                        <div class="w-2 h-2 rounded-full" :class="loading ? 'bg-primary' : 'bg-emerald-500'"></div>
                        {{ loading ? 'Scanning URL...' : 'System Ready' }}
                    </div>

                    <!-- URL Input -->
                    <div class="w-full max-w-2xl space-y-4">
                        <div class="relative group">
                            <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                <Search
                                    class="h-5 w-5 text-muted-foreground group-focus-within:text-primary transition-colors" />
                            </div>
                            <input v-model="urlInput" type="url"
                                placeholder="Enter a suspicious URL (e.g., http://example.com)"
                                class="w-full pl-11 pr-4 py-4 bg-background border-2 border-border rounded-xl focus:border-primary focus:ring-4 focus:ring-primary/10 outline-none transition-all text-lg shadow-sm"
                                @keyup.enter="submitLink" />
                        </div>

                        <button type="button"
                            class="glass-button w-full px-8 py-4 rounded-xl font-medium flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed text-lg hover:scale-[1.01] active:scale-[0.99] transition-all"
                            :disabled="!urlInput || loading" @click="submitLink">
                            <span v-if="loading" class="flex items-center gap-2">
                                <RefreshCw class="w-5 h-5 animate-spin" /> Processing ({{ elapsedSeconds }}s)
                            </span>
                            <span v-else class="flex items-center gap-2">
                                Analyze Link
                                <ArrowRight class="w-5 h-5" />
                            </span>
                        </button>
                    </div>

                    <!-- Error Message -->
                    <div v-if="errorMessage"
                        class="w-full max-w-xl p-4 bg-destructive/10 border border-destructive/20 rounded-xl flex items-start gap-3 text-destructive animate-slide-up">
                        <AlertTriangle class="w-5 h-5 shrink-0 mt-0.5" />
                        <p class="text-sm">{{ errorMessage }}</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Results Section -->
        <div v-if="analysisResult" class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-8 animate-slide-up pb-20">

            <!-- Overall Risk Banner -->
            <div v-if="overallRisk" class="rounded-2xl border-2 p-6 transition-all"
                :class="[overallRisk.bgColor, overallRisk.borderColor]">
                <div class="flex flex-col md:flex-row md:items-center gap-4">
                    <div class="flex items-center gap-4">
                        <div class="p-3 rounded-xl" :class="overallRisk.bgColor">
                            <component :is="overallRisk.icon" class="w-10 h-10" :class="overallRisk.color" />
                        </div>
                        <div>
                            <h2 class="text-2xl font-bold" :class="overallRisk.color">{{ overallRisk.label }}</h2>
                            <p class="text-muted-foreground">Overall threat assessment</p>
                        </div>
                    </div>
                    <div class="flex-1 md:text-right">
                        <div class="flex flex-wrap gap-2 md:justify-end">
                            <span v-for="factor in overallRisk.factors" :key="factor"
                                class="px-3 py-1 text-xs font-medium rounded-full"
                                :class="[overallRisk.bgColor, overallRisk.color]">
                                {{ factor }}
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- URL Info Card -->
            <div class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl p-6">
                <div class="flex items-center gap-3 mb-4">
                    <Globe class="w-5 h-5 text-primary" />
                    <h3 class="font-semibold">Analyzed URL</h3>
                </div>
                <div class="bg-muted/50 rounded-xl p-4 font-mono text-sm break-all flex items-center gap-2">
                    <span class="text-muted-foreground">{{ formatUrl(urlInput).protocol }}://</span>
                    <span class="text-primary font-medium">{{ formatUrl(urlInput).domain }}</span>
                    <span class="text-muted-foreground">{{ formatUrl(urlInput).path }}</span>
                    <button @click="copyToClipboard(urlInput, 'url')"
                        class="ml-auto p-1 hover:bg-muted rounded transition-colors">
                        <Check v-if="copiedField === 'url'" class="w-4 h-4 text-emerald-500" />
                        <Copy v-else class="w-4 h-4 text-muted-foreground" />
                    </button>
                </div>
                <!-- Effective URL (if redirects detected) -->
                <div v-if="sublimeMlData?.redirect_count && sublimeMlData.redirect_count > 0" class="mt-4">
                    <div class="flex items-center gap-2 text-sm mb-3">
                        <ArrowRight class="w-4 h-4 text-orange-500" />
                        <span class="text-orange-600 font-medium">Redirected to:</span>
                    </div>
                    <div
                        class="bg-orange-500/10 border border-orange-500/30 rounded-xl p-4 font-mono text-sm break-all">
                        <span class="text-orange-600">{{ sublimeMlData.effective_url }}</span>
                    </div>
                    <!-- Redirect Chain (collapsible) -->
                    <details v-if="sublimeMlData?.redirects && sublimeMlData.redirects.length > 1" class="mt-3">
                        <summary
                            class="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer hover:text-foreground transition-colors">
                            <Activity class="w-4 h-4" />
                            <span>Redirect Chain ({{ sublimeMlData.redirects.length }} hops)</span>
                        </summary>
                        <div class="mt-2 space-y-1 pl-6">
                            <div v-for="(redirectUrl, idx) in sublimeMlData.redirects" :key="idx"
                                class="flex items-center gap-2 text-xs font-mono bg-muted/30 rounded px-3 py-2">
                                <span class="text-muted-foreground w-4">{{ idx + 1 }}.</span>
                                <span class="truncate">{{ redirectUrl }}</span>
                            </div>
                        </div>
                    </details>
                </div>
            </div>

            <!-- Summary Cards Grid -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <!-- Sublime ML Verdict -->
                <div class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl p-6">
                    <div class="flex items-center gap-2 mb-4">
                        <Shield class="w-5 h-5 text-primary" />
                        <h3 class="text-sm font-medium text-muted-foreground">Sublime ML Analysis</h3>
                    </div>
                    <div v-if="sublimeVerdict" class="space-y-4">
                        <div class="flex items-center gap-4">
                            <component :is="sublimeVerdict.icon" class="w-12 h-12" :class="sublimeVerdict.color" />
                            <div>
                                <div class="text-2xl font-bold" :class="sublimeVerdict.color">{{ sublimeVerdict.label }}
                                </div>
                                <div class="text-sm text-muted-foreground">{{ sublimeVerdict.description }}</div>
                            </div>
                        </div>
                        <!-- Risk Score Bar -->
                        <div v-if="sublimeVerdict.score !== null && sublimeVerdict.score !== undefined"
                            class="space-y-2">
                            <div class="flex justify-between text-sm">
                                <span class="text-muted-foreground">Risk Score</span>
                                <span class="font-medium" :class="sublimeVerdict.color">{{ (sublimeVerdict.score *
                                    100).toFixed(0) }}%</span>
                            </div>
                            <div class="h-2 bg-muted rounded-full overflow-hidden">
                                <div class="h-full rounded-full transition-all duration-500"
                                    :class="sublimeVerdict.label === 'Malicious' ? 'bg-red-500' : sublimeVerdict.label === 'Suspicious' ? 'bg-yellow-500' : 'bg-emerald-500'"
                                    :style="{ width: `${sublimeVerdict.score * 100}%` }"></div>
                            </div>
                        </div>
                        <!-- Computer Vision Indicators -->
                        <div class="flex flex-wrap gap-2 pt-2 border-t border-border/50">
                            <span v-if="sublimeVerdict.containsLogin"
                                class="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-600">
                                <KeyRound class="w-3 h-3" /> Login Form
                            </span>
                            <span v-if="sublimeVerdict.containsCaptcha"
                                class="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-blue-500/20 text-blue-600">
                                <ShieldCheck class="w-3 h-3" /> CAPTCHA
                            </span>
                            <span v-if="sublimeMlData?.redirect_count && sublimeMlData.redirect_count > 0"
                                class="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-orange-500/20 text-orange-600">
                                <ArrowRight class="w-3 h-3" /> {{ sublimeMlData.redirect_count }} Redirect{{
                                    sublimeMlData.redirect_count > 1 ? 's' : '' }}
                            </span>
                            <span
                                v-if="!sublimeVerdict.containsLogin && !sublimeVerdict.containsCaptcha && (!sublimeMlData?.redirect_count || sublimeMlData.redirect_count === 0)"
                                class="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-emerald-500/20 text-emerald-600">
                                <CheckCircle class="w-3 h-3" /> No suspicious elements
                            </span>
                        </div>
                    </div>
                    <div v-else class="space-y-3">
                        <div class="flex items-center gap-4">
                            <Info class="w-12 h-12 text-muted-foreground/50" />
                            <div>
                                <div class="text-lg font-semibold text-muted-foreground">Not Available</div>
                                <div class="text-sm text-muted-foreground/70">Analysis not possible for this URL</div>
                            </div>
                        </div>
                        <p class="text-xs text-muted-foreground/60 leading-relaxed">
                            ML analysis works best on web pages with login forms. Direct file downloads and IP-based
                            URLs may not be analyzable.
                        </p>
                    </div>
                </div>

                <!-- VirusTotal Stats -->
                <div class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl p-6">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center gap-2">
                            <Bug class="w-5 h-5 text-primary" />
                            <h3 class="text-sm font-medium text-muted-foreground">VirusTotal Detections</h3>
                        </div>
                        <a v-if="getVtUrl()" :href="getVtUrl()" target="_blank"
                            class="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-muted-foreground border border-border rounded-lg hover:bg-muted/50 transition-colors">
                            <ExternalLink class="w-3.5 h-3.5" />
                            View on VT
                        </a>
                    </div>
                    <div v-if="vtStats" class="space-y-3">
                        <div class="flex items-center justify-between p-3 bg-red-500/10 rounded-lg">
                            <div class="flex items-center gap-2">
                                <XCircle class="w-5 h-5 text-red-500" />
                                <span class="font-medium text-red-500">Malicious</span>
                            </div>
                            <span class="text-2xl font-bold text-red-500">{{ vtStats.malicious }}</span>
                        </div>
                        <div class="flex items-center justify-between p-3 bg-yellow-500/10 rounded-lg">
                            <div class="flex items-center gap-2">
                                <AlertTriangle class="w-5 h-5 text-yellow-500" />
                                <span class="font-medium text-yellow-500">Suspicious</span>
                            </div>
                            <span class="text-xl font-bold text-yellow-500">{{ vtStats.suspicious }}</span>
                        </div>
                        <div class="flex items-center justify-between p-3 bg-emerald-500/10 rounded-lg">
                            <div class="flex items-center gap-2">
                                <CheckCircle class="w-5 h-5 text-emerald-500" />
                                <span class="font-medium text-emerald-500">Clean</span>
                            </div>
                            <span class="text-xl font-bold text-emerald-500">{{ vtStats.harmless + vtStats.undetected
                                }}</span>
                        </div>
                    </div>
                    <div v-else class="text-muted-foreground flex items-center gap-2">
                        <Info class="w-4 h-4" />
                        No VirusTotal data available
                    </div>
                </div>

                <!-- Website Preview with Retry Functionality -->
                <div class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl p-6">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center gap-2">
                            <Eye class="w-5 h-5 text-primary" />
                            <h3 class="text-sm font-medium text-muted-foreground">Website Preview</h3>
                        </div>
                        <div class="flex items-center gap-2">
                            <!-- View on URLscan button -->
                            <a v-if="getUrlscanUrl()" :href="getUrlscanUrl()" target="_blank"
                                class="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-primary bg-primary/10 hover:bg-primary/20 rounded-lg transition-colors">
                                <ExternalLink class="w-3.5 h-3.5" />
                                View on URLscan
                            </a>
                        </div>
                    </div>

                    <!-- Screenshot with loading/retry logic -->
                    <div v-if="screenshotUrl && !screenshotBroken" class="space-y-3">
                        <a :href="analysisResult.urlscan?.result_url || screenshotUrl" target="_blank"
                            class="block aspect-video bg-muted rounded-lg overflow-hidden border border-border/50 relative group cursor-pointer">
                            <!-- Loading overlay -->
                            <div v-if="screenshotLoading"
                                class="absolute inset-0 flex items-center justify-center bg-muted z-10">
                                <div class="text-center text-muted-foreground">
                                    <Loader2 class="w-8 h-8 mx-auto mb-2 animate-spin" />
                                    <p class="text-xs">Loading screenshot...</p>
                                </div>
                            </div>
                            <img :src="screenshotUrl"
                                class="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
                                alt="Website Screenshot" @load="onScreenshotLoad" @error="onScreenshotError"
                                @loadstart="screenshotLoading = true; startScreenshotTimeout()" />
                            <div
                                class="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                                <div class="text-center text-white">
                                    <ExternalLink class="w-8 h-8 mx-auto mb-2" />
                                    <span class="text-sm">View Full Report</span>
                                </div>
                            </div>
                        </a>
                    </div>

                    <!-- Fallback to Sublime Screenshot (when URLscan has no screenshot or it's broken) -->
                    <div v-else-if="sublimeMlData?.screenshot && (!screenshotUrl || screenshotBroken)"
                        class="space-y-3">
                        <div class="aspect-video bg-muted rounded-lg overflow-hidden border border-border/50">
                            <img :src="sublimeMlData.screenshot" class="w-full h-full object-contain"
                                alt="Sublime ML Screenshot" />
                        </div>
                        <p class="text-xs text-muted-foreground">
                            Screenshot from Sublime ML (URLscan.io unavailable)
                        </p>
                    </div>

                    <!-- No screenshot / Failed state with retry option - Click to retry -->
                    <div v-else
                        class="aspect-video bg-muted/30 rounded-lg flex items-center justify-center border border-dashed border-border cursor-pointer hover:bg-muted/50 hover:border-primary/50 transition-colors group"
                        @click="screenshotBroken ? retryScreenshot() : null">
                        <div class="text-center text-muted-foreground">
                            <RefreshCw v-if="screenshotBroken"
                                class="w-8 h-8 mx-auto mb-2 opacity-50 group-hover:opacity-100 group-hover:text-primary transition-all" />
                            <Eye v-else class="w-8 h-8 mx-auto mb-2 opacity-50" />
                            <p class="text-sm">{{ screenshotBroken ? 'Screenshot Failed' : 'No Screenshot' }}</p>
                            <p v-if="screenshotBroken"
                                class="text-xs mt-1 opacity-70 group-hover:opacity-100 group-hover:text-primary transition-colors">
                                Click to retry</p>
                            <p v-else class="text-xs mt-1 opacity-70">Could not capture</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Detailed Analysis Sections -->

            <!-- Urlscan.io Details -->
            <div class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl overflow-hidden">
                <button @click="toggleSection('urlscan')"
                    class="w-full p-6 flex items-center justify-between hover:bg-muted/30 transition-colors">
                    <div class="flex items-center gap-3">
                        <div class="p-2 bg-primary/10 rounded-lg">
                            <Globe class="w-5 h-5 text-primary" />
                        </div>
                        <div class="text-left">
                            <h3 class="font-semibold">Urlscan.io Analysis</h3>
                            <p class="text-sm text-muted-foreground">Scan results and website metadata</p>
                        </div>
                    </div>
                    <ChevronDown v-if="!expandedSections.urlscan" class="w-5 h-5 text-muted-foreground" />
                    <ChevronUp v-else class="w-5 h-5 text-muted-foreground" />
                </button>

                <div v-if="expandedSections.urlscan && urlscanDetails" class="px-6 pb-6 space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <div class="p-4 bg-muted/30 rounded-xl">
                            <div class="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                                <Fingerprint class="w-4 h-4" />
                                Scan ID
                            </div>
                            <p class="font-mono text-sm truncate">{{ urlscanDetails.scanId || 'N/A' }}</p>
                        </div>
                        <div class="p-4 bg-muted/30 rounded-xl">
                            <div class="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                                <Eye class="w-4 h-4" />
                                Visibility
                            </div>
                            <p class="font-medium capitalize">{{ urlscanDetails.visibility || 'N/A' }}</p>
                        </div>
                        <div class="p-4 bg-muted/30 rounded-xl">
                            <div class="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                                <Shield class="w-4 h-4" />
                                Verdict
                            </div>
                            <p class="font-medium capitalize" :class="{
                                'text-red-500': urlscanDetails.verdict?.includes('malicious'),
                                'text-yellow-500': urlscanDetails.verdict === 'suspicious',
                                'text-emerald-500': urlscanDetails.verdict === 'benign',
                                'text-muted-foreground': !urlscanDetails.verdict || urlscanDetails.verdict === 'no classification'
                            }">
                                {{ urlscanDetails.verdict || 'No classification' }}
                            </p>
                        </div>
                    </div>

                    <!-- Tags -->
                    <div v-if="urlscanDetails.tags && urlscanDetails.tags.length > 0">
                        <div class="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                            <Tag class="w-4 h-4" />
                            Tags
                        </div>
                        <div class="flex flex-wrap gap-2">
                            <span v-for="tag in urlscanDetails.tags" :key="tag"
                                class="px-3 py-1 text-xs font-medium rounded-full"
                                :class="tag === 'phishing' || tag === 'malware' ? 'bg-red-500/20 text-red-500' : 'bg-primary/20 text-primary'">
                                {{ tag }}
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- VirusTotal Details -->
            <div class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl overflow-hidden">
                <button @click="toggleSection('virustotal')"
                    class="w-full p-6 flex items-center justify-between hover:bg-muted/30 transition-colors">
                    <div class="flex items-center gap-3">
                        <div class="p-2 bg-primary/10 rounded-lg">
                            <Shield class="w-5 h-5 text-primary" />
                        </div>
                        <div class="text-left">
                            <h3 class="font-semibold">VirusTotal Intelligence</h3>
                            <p class="text-sm text-muted-foreground">Domain reputation and analysis history</p>
                        </div>
                    </div>
                    <ChevronDown v-if="!expandedSections.virustotal" class="w-5 h-5 text-muted-foreground" />
                    <ChevronUp v-else class="w-5 h-5 text-muted-foreground" />
                </button>

                <div v-if="expandedSections.virustotal && vtDetails" class="px-6 pb-6 space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div class="p-4 bg-muted/30 rounded-xl">
                            <div class="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                                <Activity class="w-4 h-4" />
                                Reputation Score
                            </div>
                            <p class="text-2xl font-bold"
                                :class="vtDetails.reputation < 0 ? 'text-red-500' : vtDetails.reputation > 0 ? 'text-emerald-500' : 'text-muted-foreground'">
                                {{ vtDetails.reputation }}
                            </p>
                        </div>
                        <div class="p-4 bg-muted/30 rounded-xl">
                            <div class="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                                <Clock class="w-4 h-4" />
                                Last Analysis
                            </div>
                            <p class="font-medium text-sm">{{ vtDetails.lastAnalysisDate || 'N/A' }}</p>
                        </div>
                        <div class="p-4 bg-muted/30 rounded-xl">
                            <div class="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                                <Building class="w-4 h-4" />
                                Registrar
                            </div>
                            <p class="font-medium text-sm truncate">{{ vtDetails.registrar || 'N/A' }}</p>
                        </div>
                        <div class="p-4 bg-muted/30 rounded-xl">
                            <div class="flex items-center gap-2 text-sm text-muted-foreground mb-1">
                                <Clock class="w-4 h-4" />
                                Domain Created
                            </div>
                            <p class="font-medium text-sm">{{ vtDetails.creationDate || 'N/A' }}</p>
                        </div>
                    </div>

                    <!-- Categories -->
                    <div v-if="vtDetails.categories && Object.keys(vtDetails.categories).length > 0">
                        <div class="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                            <Tag class="w-4 h-4" />
                            Domain Categories
                        </div>
                        <div class="flex flex-wrap gap-2">
                            <span v-for="(category, vendor) in vtDetails.categories" :key="vendor"
                                class="px-3 py-1 text-xs font-medium rounded-full bg-muted">
                                {{ category }} <span class="text-muted-foreground">({{ vendor }})</span>
                            </span>
                        </div>
                    </div>

                    <!-- Community Votes -->
                    <div v-if="vtDetails.totalVotes">
                        <div class="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                            Community Votes
                        </div>
                        <div class="flex gap-4">
                            <div class="flex items-center gap-2">
                                <CheckCircle class="w-4 h-4 text-emerald-500" />
                                <span class="text-emerald-500 font-medium">{{ vtDetails.totalVotes.harmless }}</span>
                                <span class="text-muted-foreground text-sm">Harmless</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <XCircle class="w-4 h-4 text-red-500" />
                                <span class="text-red-500 font-medium">{{ vtDetails.totalVotes.malicious }}</span>
                                <span class="text-muted-foreground text-sm">Malicious</span>
                            </div>
                        </div>
                    </div>

                    <!-- DNS Records -->
                    <div v-if="vtDetails.lastDnsRecords && vtDetails.lastDnsRecords.length > 0">
                        <div class="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                            <Server class="w-4 h-4" />
                            DNS Records
                        </div>
                        <div class="bg-muted/30 rounded-xl overflow-hidden">
                            <table class="w-full text-sm">
                                <thead class="bg-muted/50">
                                    <tr>
                                        <th class="px-4 py-2 text-left font-medium">Type</th>
                                        <th class="px-4 py-2 text-left font-medium">Value</th>
                                        <th class="px-4 py-2 text-left font-medium">TTL</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="(record, idx) in vtDetails.lastDnsRecords.slice(0, 5)" :key="idx"
                                        class="border-t border-border/50">
                                        <td class="px-4 py-2 font-mono">{{ record.type }}</td>
                                        <td class="px-4 py-2 font-mono truncate max-w-xs">{{ record.value }}</td>
                                        <td class="px-4 py-2">{{ record.ttl }}s</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Raw JSON Data -->
            <div class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl overflow-hidden">
                <button @click="toggleSection('raw')"
                    class="w-full p-5 flex items-center justify-between hover:bg-card/30 transition-colors border-b border-border/40">
                    <div class="flex items-center gap-3">
                        <div class="p-2 bg-primary/10 rounded-lg">
                            <FileText class="w-5 h-5 text-primary" />
                        </div>
                        <div class="text-left">
                            <h3 class="font-semibold">Raw Analysis Data</h3>
                            <p class="text-sm text-muted-foreground">Complete JSON response from all sources</p>
                        </div>
                    </div>
                    <ChevronDown v-if="!expandedSections.raw" class="w-5 h-5 text-muted-foreground" />
                    <ChevronDown v-else class="w-5 h-5 text-muted-foreground rotate-180 transition-transform" />
                </button>

                <div v-if="expandedSections.raw && separatedRawData" class="p-5">
                    <div class="relative">
                        <button @click="copyToClipboard(JSON.stringify(separatedRawData, null, 2), 'raw')"
                            class="absolute top-3 right-3 z-10 p-2 bg-muted hover:bg-muted/80 rounded-lg transition-colors">
                            <Check v-if="copiedField === 'raw'" class="w-4 h-4 text-emerald-500" />
                            <Copy v-else class="w-4 h-4 text-muted-foreground" />
                        </button>
                        <div
                            class="border border-border/40 rounded-xl p-4 overflow-auto max-h-[500px] text-sm font-mono">
                            <!-- JSON Tree View - Same design as MDM View -->
                            <template v-for="(value, key) in separatedRawData" :key="`raw.${key}`">
                                <div class="py-0.5">
                                    <!-- Object/Array - Collapsible -->
                                    <template v-if="value !== null && typeof value === 'object'">
                                        <button @click="toggleJsonNode(`raw.${key}`)"
                                            class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                            <ChevronRight
                                                class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                                :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}`) }" />
                                            <span class="text-foreground">{{ key }}:</span>
                                            <span class="text-muted-foreground">{{ getItemLabel(value) }}</span>
                                        </button>
                                        <!-- Level 2 -->
                                        <div v-if="isJsonNodeExpanded(`raw.${key}`)"
                                            class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                            <template v-for="(val2, key2) in (value as object)"
                                                :key="`raw.${key}.${key2}`">
                                                <div class="py-0.5">
                                                    <template v-if="val2 !== null && typeof val2 === 'object'">
                                                        <button @click="toggleJsonNode(`raw.${key}.${key2}`)"
                                                            class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                                            <ChevronRight
                                                                class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                                                :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}.${key2}`) }" />
                                                            <span class="text-foreground">{{ key2 }}:</span>
                                                            <span class="text-muted-foreground">{{ getItemLabel(val2)
                                                            }}</span>
                                                        </button>
                                                        <!-- Level 3 -->
                                                        <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}`)"
                                                            class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                                            <template v-for="(val3, key3) in (val2 as object)"
                                                                :key="`raw.${key}.${key2}.${key3}`">
                                                                <div class="py-0.5">
                                                                    <template
                                                                        v-if="val3 !== null && typeof val3 === 'object'">
                                                                        <button
                                                                            @click="toggleJsonNode(`raw.${key}.${key2}.${key3}`)"
                                                                            class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                                                            <ChevronRight
                                                                                class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                                                                :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}.${key2}.${key3}`) }" />
                                                                            <span class="text-foreground">{{ key3
                                                                            }}:</span>
                                                                            <span class="text-muted-foreground">{{
                                                                                getItemLabel(val3) }}</span>
                                                                        </button>
                                                                        <!-- Level 4 -->
                                                                        <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}.${key3}`)"
                                                                            class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                                                            <template v-for="(val4, key4) in (val3 as object)"
                                                                                :key="`raw.${key}.${key2}.${key3}.${key4}`">
                                                                                <div class="py-0.5">
                                                                                    <template
                                                                                        v-if="val4 !== null && typeof val4 === 'object'">
                                                                                        <button
                                                                                            @click="toggleJsonNode(`raw.${key}.${key2}.${key3}.${key4}`)"
                                                                                            class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                                                                            <ChevronRight
                                                                                                class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                                                                                :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}.${key2}.${key3}.${key4}`) }" />
                                                                                            <span class="text-foreground">{{ key4 }}:</span>
                                                                                            <span class="text-muted-foreground">{{ getItemLabel(val4) }}</span>
                                                                                        </button>
                                                                                        <!-- Level 5 -->
                                                                                        <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}.${key3}.${key4}`)"
                                                                                            class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                                                                            <template v-for="(val5, key5) in (val4 as object)"
                                                                                                :key="`raw.${key}.${key2}.${key3}.${key4}.${key5}`">
                                                                                                <div class="py-0.5">
                                                                                                    <template
                                                                                                        v-if="val5 !== null && typeof val5 === 'object'">
                                                                                                        <button
                                                                                                            @click="toggleJsonNode(`raw.${key}.${key2}.${key3}.${key4}.${key5}`)"
                                                                                                            class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                                                                                            <ChevronRight
                                                                                                                class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                                                                                                :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}.${key2}.${key3}.${key4}.${key5}`) }" />
                                                                                                            <span class="text-foreground">{{ key5 }}:</span>
                                                                                                            <span class="text-muted-foreground">{{ getItemLabel(val5) }}</span>
                                                                                                        </button>
                                                                                                        <!-- Level 6+ - Show as JSON -->
                                                                                                        <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}.${key3}.${key4}.${key5}`)"
                                                                                                            class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                                                                                            <pre class="text-foreground whitespace-pre-wrap break-words text-xs">{{ prettyJson(val5) }}</pre>
                                                                                                        </div>
                                                                                                    </template>
                                                                                                    <template v-else>
                                                                                                        <div class="flex items-start gap-1.5 pl-4">
                                                                                                            <span class="text-foreground shrink-0">{{ key5 }}:</span>
                                                                                                            <span class="text-muted-foreground ml-1 break-all">{{ val5 === null ? 'null' : val5 }}</span>
                                                                                                        </div>
                                                                                                    </template>
                                                                                                </div>
                                                                                            </template>
                                                                                        </div>
                                                                                    </template>
                                                                                    <template v-else>
                                                                                        <div class="flex items-start gap-1.5 pl-4">
                                                                                            <span class="text-foreground shrink-0">{{ key4 }}:</span>
                                                                                            <span class="text-muted-foreground ml-1 break-all">{{ val4 === null ? 'null' : val4 }}</span>
                                                                                        </div>
                                                                                    </template>
                                                                                </div>
                                                                            </template>
                                                                        </div>
                                                                    </template>
                                                                    <template v-else>
                                                                        <div class="flex items-start gap-1.5 pl-4">
                                                                            <span class="text-foreground shrink-0">{{
                                                                                key3 }}:</span>
                                                                            <span
                                                                                class="text-muted-foreground ml-1 break-all">{{
                                                                                    val3 === null ? 'null' : val3 }}</span>
                                                                        </div>
                                                                    </template>
                                                                </div>
                                                            </template>
                                                        </div>
                                                    </template>
                                                    <template v-else>
                                                        <div class="flex items-start gap-1.5 pl-4">
                                                            <span class="text-foreground shrink-0">{{ key2 }}:</span>
                                                            <span class="text-muted-foreground ml-1 break-all">{{ val2
                                                                === null ? 'null' : val2 }}</span>
                                                        </div>
                                                    </template>
                                                </div>
                                            </template>
                                        </div>
                                    </template>
                                    <!-- Simple value -->
                                    <template v-else>
                                        <div class="flex items-start gap-1.5 pl-4">
                                            <span class="text-foreground shrink-0">{{ key }}:</span>
                                            <span class="text-muted-foreground ml-1 break-all">{{ value === null ?
                                                'null' : value }}</span>
                                        </div>
                                    </template>
                                </div>
                            </template>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>
</template>
