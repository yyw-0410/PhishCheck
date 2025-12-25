<script setup lang="ts">
import { ref, computed, onUnmounted, watch } from 'vue'
import {
    FileSearch,
    Upload,
    RefreshCw,
    AlertTriangle,
    CheckCircle,
    XCircle,
    AlertOctagon,
    Shield,
    Clock,
    Tag,
    ChevronDown,
    ChevronUp,
    ChevronRight,
    Copy,
    Check,
    Info,
    Fingerprint,
    File,
    Hash,
    Activity,
    HardDrive,
    FileType,
    Calendar,
    Search,
    Trash2,
    ExternalLink,
    Network,
    Globe,
    Cpu,
    Target,
    UploadCloud
} from 'lucide-vue-next'
import { Badge } from '@/components/ui/badge'
import { useAnalysisStore } from '@/stores/analysis'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

// Analysis store for AI chat integration
const analysisStore = useAnalysisStore()

// State
const hashInput = ref('')
const selectedFile = ref<File | null>(null)
const fileInputRef = ref<HTMLInputElement | null>(null)
const loading = ref(false)
const errorMessage = ref('')
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const analysisResult = ref<any>(null)
const copiedField = ref('')
const expandedSections = ref<Record<string, boolean>>({
    fileInfo: true,
    virustotal: true,
    hybridanalysis: true,
    haFileType: false,
    details: false,
    raw: false
})
const isDragging = ref(false)
const activeTab = ref<'upload' | 'hash'>('upload')

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
    // Clear file analysis from store when leaving
    analysisStore.setFileAnalysisResult(null)
})

// Trigger file dialog
const triggerFileDialog = () => {
    fileInputRef.value?.click()
}

// File drop handlers
const handleDragOver = (e: DragEvent) => {
    e.preventDefault()
    isDragging.value = true
}

const handleDragLeave = () => {
    isDragging.value = false
}

const handleDrop = (e: DragEvent) => {
    e.preventDefault()
    isDragging.value = false
    const files = e.dataTransfer?.files
    if (files && files.length > 0 && files[0]) {
        selectedFile.value = files[0]
    }
}

const handleFileSelect = (e: Event) => {
    const input = e.target as HTMLInputElement
    if (input.files && input.files.length > 0 && input.files[0]) {
        selectedFile.value = input.files[0]
    }
}

const clearFile = () => {
    selectedFile.value = null
    // Reset file input
    const fileInput = document.getElementById('file-input') as HTMLInputElement
    if (fileInput) fileInput.value = ''
}

// Submit analysis
const submitFileAnalysis = async () => {
    if (!selectedFile.value) return

    loading.value = true
    errorMessage.value = ''
    analysisResult.value = null
    startTimer()

    try {
        const formData = new FormData()
        formData.append('file', selectedFile.value)

        const response = await fetch(`${API_BASE_URL}/api/v1/analysis/file`, {
            method: 'POST',
            body: formData,
            credentials: 'include',
        })

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}))
            throw new Error(errorData.detail || `Backend responded with ${response.status}`)
        }

        analysisResult.value = await response.json()
        // Sync to store for AI chat integration
        analysisStore.setFileAnalysisResult(analysisResult.value)
    } catch (error) {
        console.error('File analysis failed:', error)
        errorMessage.value = error instanceof Error ? error.message : 'Failed to analyze file. Please try again.'
    } finally {
        loading.value = false
        stopTimer()
    }
}

const submitHashAnalysis = async () => {
    if (!hashInput.value) return

    loading.value = true
    errorMessage.value = ''
    analysisResult.value = null
    startTimer()

    try {
        // Determine hash type by length
        const hash = hashInput.value.trim().toLowerCase()
        let queryParam = ''
        if (hash.length === 64) {
            queryParam = `sha256=${hash}`
        } else if (hash.length === 32) {
            queryParam = `md5=${hash}`
        } else {
            throw new Error('Invalid hash format. Please provide a SHA256 (64 chars) or MD5 (32 chars) hash.')
        }

        const response = await fetch(`${API_BASE_URL}/api/v1/analysis/file?${queryParam}`, {
            method: 'POST',
            credentials: 'include',
        })

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}))
            throw new Error(errorData.detail || `Backend responded with ${response.status}`)
        }

        analysisResult.value = await response.json()
        // Sync to store for AI chat integration
        analysisStore.setFileAnalysisResult(analysisResult.value)
    } catch (error) {
        console.error('Hash lookup failed:', error)
        errorMessage.value = error instanceof Error ? error.message : 'Failed to look up hash. Please try again.'
    } finally {
        loading.value = false
        stopTimer()
    }
}

// Overall risk assessment - score-based thresholds with industry labels
const overallRisk = computed(() => {
    if (!analysisResult.value) return null

    const score = analysisResult.value.risk_score ?? 0
    const factors = analysisResult.value.risk_factors || []
    const verdict = analysisResult.value.overall_verdict

    // Handle not_found case specially
    if (verdict === 'not_found') {
        return { level: 'unknown', label: 'Not Found', score, factors, color: 'text-gray-600', bgColor: 'bg-muted/50', borderColor: 'border-border', icon: Info }
    }

    // Score-based thresholds (same as Link Analysis)
    if (score >= 70) {
        return { level: 'critical', label: 'Malicious', score, factors, color: 'text-red-600', bgColor: 'bg-red-500/10', borderColor: 'border-red-500/30', icon: XCircle }
    } else if (score >= 40) {
        return { level: 'high', label: 'Suspicious', score, factors, color: 'text-orange-600', bgColor: 'bg-orange-500/10', borderColor: 'border-orange-500/30', icon: AlertOctagon }
    } else if (score >= 20) {
        return { level: 'medium', label: 'Low Risk', score, factors, color: 'text-yellow-600', bgColor: 'bg-yellow-500/10', borderColor: 'border-yellow-500/30', icon: AlertTriangle }
    }
    return { level: 'safe', label: 'Clean', score, factors, color: 'text-emerald-600', bgColor: 'bg-emerald-500/10', borderColor: 'border-emerald-500/30', icon: CheckCircle }
})

// VirusTotal stats
const vtStats = computed(() => {
    const vt = analysisResult.value?.virustotal
    if (!vt?.stats) return null

    const stats = vt.stats
    const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)

    return {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0,
        undetected: stats.undetected || 0,
        total,
        detectionRate: total > 0 ? Math.round(((stats.malicious || 0) / total) * 100) : 0
    }
})

// File info
const fileInfo = computed(() => {
    const info = analysisResult.value?.file_info
    const vt = analysisResult.value?.virustotal
    if (!info && !vt) return null

    return {
        filename: info?.filename || vt?.meaningful_name || 'Unknown',
        size: info?.size || vt?.size,
        sha256: info?.sha256 || vt?.sha256,
        md5: info?.md5 || vt?.md5,
        sha1: info?.sha1 || vt?.sha1,
        contentType: info?.content_type || vt?.type_description,
        typeTag: vt?.type_tag,
        timesSubmitted: vt?.times_submitted,
        reputation: vt?.reputation,
        lastAnalysisDate: vt?.last_analysis_date ? new Date(vt.last_analysis_date * 1000).toLocaleString() : null,
        firstSubmission: vt?.first_submission_date ? new Date(vt.first_submission_date * 1000).toLocaleString() : null,
        tags: vt?.tags || [],
        names: vt?.names || []
    }
})

// Computed: Get signature info from multiple possible locations
const signatureInfo = computed(() => {
    const vt = analysisResult.value?.virustotal
    if (!vt) return null

    // Check direct path first
    if (vt.signature_info && Object.keys(vt.signature_info).length > 0) {
        return vt.signature_info
    }

    // Check raw_data.attributes.signature_info
    if (vt.raw_data?.attributes?.signature_info && Object.keys(vt.raw_data.attributes.signature_info).length > 0) {
        return vt.raw_data.attributes.signature_info
    }

    // Check raw_data.attributes.pe_info for Windows PE signature
    const peInfo = vt.raw_data?.attributes?.pe_info
    if (peInfo?.signature) {
        return peInfo.signature
    }

    return null
})

// Helpers
function toggleSection(section: string) {
    expandedSections.value[section] = !expandedSections.value[section]
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

function formatFileSize(bytes: number | undefined): string {
    if (!bytes) return 'Unknown'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
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
                    <FileSearch class="w-10 h-10 text-primary" />
                </div>

                <h1
                    class="text-5xl md:text-6xl font-bold tracking-tight text-gray-900 dark:bg-gradient-to-b dark:from-white dark:to-white/60 dark:bg-clip-text dark:text-transparent drop-shadow-sm">
                    File Analysis
                </h1>

                <p class="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
                    Upload a file or enter a hash to check for threats using <span
                        class="text-primary font-medium">VirusTotal</span> and <span
                        class="text-primary font-medium">Hybrid Analysis</span>.
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
                        {{ loading ? 'Analyzing File...' : 'System Ready' }}
                    </div>

                    <!-- Tab Switcher -->
                    <div class="w-full max-w-2xl">
                        <div class="flex bg-muted/50 p-1 rounded-xl mb-6">
                            <button @click="activeTab = 'upload'" :class="[
                                'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-medium transition-all',
                                activeTab === 'upload'
                                    ? 'bg-background shadow-sm text-foreground'
                                    : 'text-muted-foreground hover:text-foreground'
                            ]">
                                <Upload class="h-4 w-4" />
                                Upload File
                            </button>
                            <button @click="activeTab = 'hash'" :class="[
                                'flex-1 flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-medium transition-all',
                                activeTab === 'hash'
                                    ? 'bg-background shadow-sm text-foreground'
                                    : 'text-muted-foreground hover:text-foreground'
                            ]">
                                <Hash class="h-4 w-4" />
                                Hash Lookup
                            </button>
                        </div>

                        <!-- Upload Tab Content -->
                        <div v-if="activeTab === 'upload'" class="space-y-4">
                            <!-- File Drop Zone -->
                            <div @dragover="handleDragOver" @dragleave="handleDragLeave" @drop="handleDrop"
                                class="relative cursor-pointer" @click="triggerFileDialog">
                                <input ref="fileInputRef" type="file" class="hidden" @change="handleFileSelect" />

                                <div class="relative flex flex-col items-center justify-center p-12 border-2 border-dashed rounded-2xl transition-all duration-300 bg-card/50 backdrop-blur-sm group-hover:bg-card/80"
                                    :class="[
                                        isDragging
                                            ? 'border-primary bg-card/70 scale-[1.02] shadow-xl shadow-black/20'
                                            : selectedFile
                                                ? 'border-emerald-500 bg-emerald-50/50 dark:bg-emerald-950/20'
                                                : 'border-border shadow-sm hover:shadow-md hover:border-primary/50'
                                    ]">
                                    <div v-if="!selectedFile">
                                        <div
                                            class="p-4 bg-background rounded-full shadow-sm mb-4 mx-auto w-fit group-hover:scale-110 transition-transform duration-300">
                                            <Upload class="w-8 h-8 text-primary" />
                                        </div>
                                        <h3 class="text-xl font-semibold mb-2 text-center">
                                            Drop your file here
                                        </h3>
                                        <p class="text-muted-foreground text-center">
                                            or <span class="text-primary font-medium">click to browse</span>
                                        </p>
                                        <p class="text-xs text-muted-foreground mt-2 text-center">
                                            Supports any file type
                                        </p>
                                    </div>

                                    <div v-else class="flex items-center gap-4">
                                        <div class="p-3 bg-emerald-100 dark:bg-emerald-900/40 rounded-xl">
                                            <File class="h-8 w-8 text-emerald-600" />
                                        </div>
                                        <div class="text-left">
                                            <p class="font-semibold text-lg">{{ selectedFile.name }}</p>
                                            <p class="text-sm text-muted-foreground">{{
                                                formatFileSize(selectedFile.size) }}</p>
                                        </div>
                                        <button @click.stop="clearFile"
                                            class="ml-4 p-2 hover:bg-destructive/10 rounded-lg transition-colors">
                                            <Trash2 class="h-5 w-5 text-muted-foreground hover:text-destructive" />
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <button type="button"
                                class="glass-button w-full px-8 py-4 rounded-xl font-medium flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed text-lg hover:scale-[1.01] active:scale-[0.99] transition-all"
                                :disabled="!selectedFile || loading" @click="submitFileAnalysis">
                                <span v-if="loading" class="flex items-center gap-2">
                                    <RefreshCw class="w-5 h-5 animate-spin" /> Processing ({{ elapsedSeconds }}s)
                                </span>
                                <span v-else class="flex items-center gap-2">
                                    Analyze File
                                    <FileSearch class="w-5 h-5" />
                                </span>
                            </button>
                        </div>

                        <!-- Hash Tab Content -->
                        <div v-if="activeTab === 'hash'" class="space-y-4">
                            <div class="relative group">
                                <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                                    <Fingerprint
                                        class="h-5 w-5 text-muted-foreground group-focus-within:text-primary transition-colors" />
                                </div>
                                <input v-model="hashInput" type="text" placeholder="Enter SHA256 or MD5 hash..."
                                    class="w-full pl-11 pr-4 py-4 bg-background border-2 border-border rounded-xl focus:border-primary focus:ring-4 focus:ring-primary/10 outline-none transition-all text-lg shadow-sm font-mono text-sm"
                                    @keyup.enter="submitHashAnalysis" />
                            </div>
                            <p class="text-xs text-muted-foreground text-center">
                                SHA256 (64 characters) or MD5 (32 characters)
                            </p>
                            <button type="button"
                                class="glass-button w-full px-8 py-4 rounded-xl font-medium flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed text-lg hover:scale-[1.01] active:scale-[0.99] transition-all"
                                :disabled="!hashInput || loading" @click="submitHashAnalysis">
                                <span v-if="loading" class="flex items-center gap-2">
                                    <RefreshCw class="w-5 h-5 animate-spin" /> Processing ({{ elapsedSeconds }}s)
                                </span>
                                <span v-else class="flex items-center gap-2">
                                    Look Up Hash
                                    <Search class="w-5 h-5" />
                                </span>
                            </button>
                        </div>
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
            <div v-if="overallRisk" class="rounded-2xl border-2 p-6 transition-all" :class="{
                'bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-900': overallRisk.level === 'critical',
                'bg-orange-50 dark:bg-orange-950/20 border-orange-200 dark:border-orange-900': overallRisk.level === 'high',
                'bg-emerald-50 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900': overallRisk.level === 'safe',
                'bg-muted/50 border-border': overallRisk.level === 'unknown'
            }">
                <div class="flex flex-col md:flex-row md:items-center gap-4">
                    <div class="flex items-center gap-4">
                        <div class="p-3 rounded-xl" :class="{
                            'bg-red-100 dark:bg-red-900/40': overallRisk.level === 'critical',
                            'bg-orange-100 dark:bg-orange-900/40': overallRisk.level === 'high',
                            'bg-emerald-100 dark:bg-emerald-900/40': overallRisk.level === 'safe',
                            'bg-muted': overallRisk.level === 'unknown'
                        }">
                            <component :is="overallRisk.icon" class="w-10 h-10" :class="{
                                'text-red-600': overallRisk.level === 'critical',
                                'text-orange-600': overallRisk.level === 'high',
                                'text-emerald-600': overallRisk.level === 'safe',
                                'text-muted-foreground': overallRisk.level === 'unknown'
                            }" />
                        </div>
                        <div>
                            <h2 class="text-2xl font-bold" :class="{
                                'text-red-700 dark:text-red-400': overallRisk.level === 'critical',
                                'text-orange-700 dark:text-orange-400': overallRisk.level === 'high',
                                'text-emerald-700 dark:text-emerald-400': overallRisk.level === 'safe',
                                'text-muted-foreground': overallRisk.level === 'unknown'
                            }">{{ overallRisk.label }}</h2>
                            <p class="text-muted-foreground">Overall threat assessment</p>
                        </div>
                    </div>
                    <div class="flex-1 md:text-right">
                        <p class="text-sm text-muted-foreground">Risk Score</p>
                        <p class="text-4xl font-bold" :class="{
                            'text-red-600': overallRisk.level === 'critical',
                            'text-orange-600': overallRisk.level === 'high',
                            'text-emerald-600': overallRisk.level === 'safe',
                            'text-muted-foreground': overallRisk.level === 'unknown'
                        }">{{ overallRisk.score }}</p>
                    </div>
                </div>
                <!-- Risk Factors -->
                <div v-if="overallRisk.factors && overallRisk.factors.length > 0" class="mt-4 pt-4 border-t" :class="{
                    'border-red-200 dark:border-red-800': overallRisk.level === 'critical',
                    'border-orange-200 dark:border-orange-800': overallRisk.level === 'high',
                    'border-emerald-200 dark:border-emerald-800': overallRisk.level === 'safe',
                    'border-border': overallRisk.level === 'unknown'
                }">
                    <div class="flex flex-wrap gap-2">
                        <span v-for="factor in overallRisk.factors" :key="factor"
                            class="px-3 py-1 text-xs font-medium rounded-full" :class="{
                                'bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300': overallRisk.level === 'critical',
                                'bg-orange-100 dark:bg-orange-900/50 text-orange-700 dark:text-orange-300': overallRisk.level === 'high',
                                'bg-emerald-100 dark:bg-emerald-900/50 text-emerald-700 dark:text-emerald-300': overallRisk.level === 'safe',
                                'bg-muted text-muted-foreground': overallRisk.level === 'unknown'
                            }">
                            {{ factor }}
                        </span>
                    </div>
                </div>
            </div>

            <!-- File Information Card -->
            <div v-if="fileInfo"
                class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl overflow-hidden">
                <div class="p-6 cursor-pointer hover:bg-muted/30 transition-colors" @click="toggleSection('fileInfo')">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="p-2 bg-primary/10 rounded-lg">
                                <File class="h-5 w-5 text-primary" />
                            </div>
                            <div>
                                <h3 class="font-semibold text-lg">File Information</h3>
                                <p class="text-sm text-muted-foreground">{{ fileInfo?.filename }} • via VirusTotal</p>
                            </div>
                        </div>
                        <component :is="expandedSections.fileInfo ? ChevronUp : ChevronDown"
                            class="h-5 w-5 text-muted-foreground" />
                    </div>
                </div>
                <div v-if="expandedSections.fileInfo" class="p-6 pt-0 border-t border-border/50">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                        <!-- Basic Info -->
                        <div class="space-y-3">
                            <div class="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                                <HardDrive class="h-4 w-4 text-muted-foreground" />
                                <div>
                                    <p class="text-xs text-muted-foreground">Size</p>
                                    <p class="font-medium">{{ formatFileSize(fileInfo?.size) }}</p>
                                </div>
                            </div>
                            <div v-if="fileInfo?.contentType"
                                class="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                                <FileType class="h-4 w-4 text-muted-foreground" />
                                <div>
                                    <p class="text-xs text-muted-foreground">Type</p>
                                    <p class="font-medium">{{ fileInfo?.contentType }}</p>
                                </div>
                            </div>
                            <div v-if="fileInfo?.typeTag" class="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                                <Tag class="h-4 w-4 text-muted-foreground" />
                                <div>
                                    <p class="text-xs text-muted-foreground">Type Tag</p>
                                    <Badge variant="secondary">{{ fileInfo?.typeTag }}</Badge>
                                </div>
                            </div>
                        </div>

                        <!-- Hashes -->
                        <div class="space-y-3">
                            <div v-if="fileInfo?.sha256" class="p-3 bg-muted/50 rounded-lg">
                                <div class="flex items-center justify-between">
                                    <p class="text-xs text-muted-foreground flex items-center gap-1">
                                        <Fingerprint class="h-3 w-3" /> SHA256
                                    </p>
                                    <button class="p-1 hover:bg-muted rounded transition-colors"
                                        @click="copyToClipboard(fileInfo?.sha256 || '', 'sha256')">
                                        <Check v-if="copiedField === 'sha256'" class="h-3 w-3 text-emerald-500" />
                                        <Copy v-else class="h-3 w-3 text-muted-foreground" />
                                    </button>
                                </div>
                                <p class="font-mono text-xs break-all mt-1">{{ fileInfo?.sha256 }}</p>
                            </div>
                            <div v-if="fileInfo?.md5" class="p-3 bg-muted/50 rounded-lg">
                                <div class="flex items-center justify-between">
                                    <p class="text-xs text-muted-foreground flex items-center gap-1">
                                        <Hash class="h-3 w-3" /> MD5
                                    </p>
                                    <button class="p-1 hover:bg-muted rounded transition-colors"
                                        @click="copyToClipboard(fileInfo?.md5 || '', 'md5')">
                                        <Check v-if="copiedField === 'md5'" class="h-3 w-3 text-emerald-500" />
                                        <Copy v-else class="h-3 w-3 text-muted-foreground" />
                                    </button>
                                </div>
                                <p class="font-mono text-xs mt-1">{{ fileInfo?.md5 }}</p>
                            </div>
                            <div v-if="fileInfo?.sha1" class="p-3 bg-muted/50 rounded-lg">
                                <div class="flex items-center justify-between">
                                    <p class="text-xs text-muted-foreground">SHA1</p>
                                    <button class="p-1 hover:bg-muted rounded transition-colors"
                                        @click="copyToClipboard(fileInfo?.sha1 || '', 'sha1')">
                                        <Check v-if="copiedField === 'sha1'" class="h-3 w-3 text-emerald-500" />
                                        <Copy v-else class="h-3 w-3 text-muted-foreground" />
                                    </button>
                                </div>
                                <p class="font-mono text-xs mt-1">{{ fileInfo?.sha1 }}</p>
                            </div>
                        </div>
                    </div>

                    <!-- Tags & Names -->
                    <div v-if="fileInfo?.tags?.length" class="mt-4">
                        <p class="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                            <Tag class="h-3 w-3" /> Tags
                        </p>
                        <div class="flex flex-wrap gap-2">
                            <Badge v-for="tag in fileInfo?.tags?.slice(0, 10)" :key="tag" variant="outline"
                                class="text-xs">
                                {{ tag }}
                            </Badge>
                            <Badge v-if="(fileInfo?.tags?.length || 0) > 10" variant="secondary" class="text-xs">
                                +{{ (fileInfo?.tags?.length || 0) - 10 }} more
                            </Badge>
                        </div>
                    </div>

                    <!-- Timestamps -->
                    <div v-if="fileInfo?.lastAnalysisDate || fileInfo?.firstSubmission"
                        class="mt-4 grid grid-cols-2 gap-4">
                        <div v-if="fileInfo?.firstSubmission"
                            class="flex items-center gap-2 text-sm text-muted-foreground">
                            <Calendar class="h-4 w-4" />
                            <span>First seen: {{ fileInfo?.firstSubmission }}</span>
                        </div>
                        <div v-if="fileInfo?.lastAnalysisDate"
                            class="flex items-center gap-2 text-sm text-muted-foreground">
                            <Clock class="h-4 w-4" />
                            <span>Last analyzed: {{ fileInfo?.lastAnalysisDate }}</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- VirusTotal Results -->
            <div v-if="vtStats"
                class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl overflow-hidden">
                <div class="p-6 cursor-pointer hover:bg-muted/30 transition-colors"
                    @click="toggleSection('virustotal')">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="p-2 bg-primary/10 rounded-lg">
                                <Shield class="h-5 w-5 text-primary" />
                            </div>
                            <div>
                                <h3 class="font-semibold text-lg">VirusTotal Analysis</h3>
                                <p class="text-sm text-muted-foreground">{{ vtStats.total }} security vendors</p>
                            </div>
                        </div>
                        <div class="flex items-center gap-3">
                            <Badge :variant="vtStats.malicious > 0 ? 'destructive' : 'secondary'"
                                class="text-base px-3 py-1">
                                {{ vtStats.malicious }}/{{ vtStats.total }}
                            </Badge>
                            <component :is="expandedSections.virustotal ? ChevronUp : ChevronDown"
                                class="h-5 w-5 text-muted-foreground" />
                        </div>
                    </div>
                </div>
                <div v-if="expandedSections.virustotal" class="p-6 pt-0 border-t border-border/50">
                    <!-- Redesigned Premium Layout -->
                    <div class="mt-6 space-y-6">

                        <!-- 1. Stats Overview - Premium Cards -->
                        <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
                            <!-- Reputation -->
                            <div
                                class="group relative bg-gradient-to-br from-card to-muted/30 border border-border/50 rounded-xl p-4 hover:border-border transition-all duration-300 hover:shadow-lg hover:shadow-primary/5">
                                <div class="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                                    <div class="p-1.5 bg-primary/10 rounded-lg">
                                        <Activity class="w-3.5 h-3.5 text-primary" />
                                    </div>
                                    <span class="font-medium">Reputation</span>
                                </div>
                                <p class="text-2xl font-bold tracking-tight"
                                    :class="analysisResult.virustotal.reputation < 0 ? 'text-red-500' : (analysisResult.virustotal.reputation > 0 ? 'text-emerald-500' : 'text-foreground')">
                                    {{ analysisResult.virustotal.reputation >= 0 ? '+' : '' }}{{
                                        analysisResult.virustotal.reputation }}
                                </p>
                            </div>
                            <!-- Last Analysis -->
                            <div
                                class="group relative bg-gradient-to-br from-card to-muted/30 border border-border/50 rounded-xl p-4 hover:border-border transition-all duration-300 hover:shadow-lg hover:shadow-primary/5">
                                <div class="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                                    <div class="p-1.5 bg-primary/10 rounded-lg">
                                        <Clock class="w-3.5 h-3.5 text-primary" />
                                    </div>
                                    <span class="font-medium">Last Analysis</span>
                                </div>
                                <p class="text-lg font-semibold text-foreground">
                                    {{ analysisResult.virustotal.last_analysis_date ? new
                                        Date(analysisResult.virustotal.last_analysis_date * 1000).toLocaleString() : 'N/A'
                                    }}
                                </p>
                            </div>
                            <!-- First Seen -->
                            <div
                                class="group relative bg-gradient-to-br from-card to-muted/30 border border-border/50 rounded-xl p-4 hover:border-border transition-all duration-300 hover:shadow-lg hover:shadow-primary/5">
                                <div class="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                                    <div class="p-1.5 bg-primary/10 rounded-lg">
                                        <Calendar class="w-3.5 h-3.5 text-primary" />
                                    </div>
                                    <span class="font-medium">First Seen</span>
                                </div>
                                <p class="text-lg font-semibold text-foreground">
                                    {{ analysisResult.virustotal.first_submission_date ? new
                                        Date(analysisResult.virustotal.first_submission_date * 1000).toLocaleDateString() :
                                        'N/A' }}
                                </p>
                            </div>
                            <!-- Submissions -->
                            <div
                                class="group relative bg-gradient-to-br from-card to-muted/30 border border-border/50 rounded-xl p-4 hover:border-border transition-all duration-300 hover:shadow-lg hover:shadow-primary/5">
                                <div class="flex items-center gap-2 text-sm text-muted-foreground mb-2">
                                    <div class="p-1.5 bg-primary/10 rounded-lg">
                                        <UploadCloud class="w-3.5 h-3.5 text-primary" />
                                    </div>
                                    <span class="font-medium">Submissions</span>
                                </div>
                                <p class="text-2xl font-bold tracking-tight text-foreground">
                                    {{ analysisResult.virustotal.times_submitted || 'N/A' }}
                                </p>
                            </div>
                        </div>


                        <!-- 2. Digital Signature & Sandbox Analysis - Consistent Cards -->
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <!-- Digital Signature Card -->
                            <div
                                class="bg-gradient-to-br from-card to-muted/20 border border-border/50 rounded-xl overflow-hidden">
                                <div class="flex items-center justify-between p-4 border-b border-border/30">
                                    <div class="flex items-center gap-2.5">
                                        <div class="p-1.5 bg-violet-500/10 rounded-lg">
                                            <Fingerprint class="w-4 h-4 text-violet-500" />
                                        </div>
                                        <h4 class="font-semibold text-sm">Digital Signature</h4>
                                    </div>
                                    <div v-if="signatureInfo?.verified === true || signatureInfo?.['Verification'] === 'Signed'"
                                        class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-emerald-500/10 border border-emerald-500/30 text-emerald-500">
                                        <CheckCircle class="w-3 h-3" />
                                        Verified
                                    </div>
                                    <div v-else-if="signatureInfo?.verified === false"
                                        class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-red-500/10 border border-red-500/30 text-red-500">
                                        <XCircle class="w-3 h-3" />
                                        Invalid
                                    </div>
                                    <div v-else-if="signatureInfo"
                                        class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-blue-500/10 border border-blue-500/30 text-blue-500">
                                        <Info class="w-3 h-3" />
                                        Signed
                                    </div>
                                </div>
                                <div class="p-4">
                                    <div v-if="signatureInfo" class="space-y-2">
                                        <div v-if="signatureInfo.product || signatureInfo['product name']"
                                            class="flex gap-3">
                                            <span class="text-sm text-muted-foreground w-20 shrink-0">Product</span>
                                            <span class="text-sm font-medium">{{ signatureInfo.product ||
                                                signatureInfo['product name'] }}</span>
                                        </div>
                                        <div v-if="signatureInfo.description" class="flex gap-3">
                                            <span class="text-sm text-muted-foreground w-20 shrink-0">Description</span>
                                            <span class="text-sm font-medium">{{ signatureInfo.description }}</span>
                                        </div>
                                        <div v-if="signatureInfo['file version']" class="flex gap-3">
                                            <span class="text-sm text-muted-foreground w-20 shrink-0">Version</span>
                                            <span class="text-sm font-medium">{{ signatureInfo['file version'] }}</span>
                                        </div>
                                        <div v-if="signatureInfo.signers" class="flex gap-3">
                                            <span class="text-sm text-muted-foreground w-20 shrink-0">Signer</span>
                                            <span class="text-sm font-mono">{{ signatureInfo.signers }}</span>
                                        </div>
                                        <div v-if="signatureInfo['original name']" class="flex gap-3">
                                            <span class="text-sm text-muted-foreground w-20 shrink-0">Original</span>
                                            <span class="text-sm font-medium">{{ signatureInfo['original name']
                                            }}</span>
                                        </div>
                                        <div v-if="signatureInfo['internal name']" class="flex gap-3">
                                            <span class="text-sm text-muted-foreground w-20 shrink-0">Internal</span>
                                            <span class="text-sm font-medium">{{ signatureInfo['internal name']
                                            }}</span>
                                        </div>
                                        <div v-if="signatureInfo.copyright || signatureInfo['legal copyright']"
                                            class="flex gap-3">
                                            <span class="text-sm text-muted-foreground w-20 shrink-0">Copyright</span>
                                            <span class="text-sm text-muted-foreground">{{ signatureInfo.copyright ||
                                                signatureInfo['legal copyright'] }}</span>
                                        </div>
                                    </div>
                                    <div v-else class="flex items-center gap-3 py-2 text-muted-foreground">
                                        <XCircle class="w-5 h-5 text-muted-foreground/40" />
                                        <span class="text-sm">No signature found</span>
                                    </div>
                                </div>
                            </div>

                            <!-- Sandbox Analysis Card -->
                            <div
                                class="bg-gradient-to-br from-card to-muted/20 border border-border/50 rounded-xl overflow-hidden">
                                <div class="flex items-center justify-between p-4 border-b border-border/30">
                                    <div class="flex items-center gap-2.5">
                                        <div class="p-1.5 bg-orange-500/10 rounded-lg">
                                            <Cpu class="w-4 h-4 text-orange-500" />
                                        </div>
                                        <h4 class="font-semibold text-sm">Sandbox Analysis</h4>
                                    </div>
                                    <!-- Show overall risk badge if any malicious -->
                                    <div v-if="analysisResult.virustotal.sandbox_verdicts && Object.values(analysisResult.virustotal.sandbox_verdicts).some((v: any) => v.category === 'malicious')"
                                        class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-red-500/10 border border-red-500/30 text-red-500">
                                        <XCircle class="w-3 h-3" />
                                        Malicious
                                    </div>
                                    <div v-else-if="analysisResult.virustotal.sandbox_verdicts && Object.values(analysisResult.virustotal.sandbox_verdicts).some((v: any) => v.category === 'suspicious')"
                                        class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-orange-500/10 border border-orange-500/30 text-orange-500">
                                        <AlertTriangle class="w-3 h-3" />
                                        Suspicious
                                    </div>
                                    <div v-else-if="analysisResult.virustotal.sandbox_verdicts && Object.keys(analysisResult.virustotal.sandbox_verdicts).length > 0"
                                        class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-emerald-500/10 border border-emerald-500/30 text-emerald-500">
                                        <CheckCircle class="w-3 h-3" />
                                        Clean
                                    </div>
                                </div>
                                <div class="p-4">
                                    <div v-if="analysisResult.virustotal.sandbox_verdicts && Object.keys(analysisResult.virustotal.sandbox_verdicts).length > 0"
                                        class="space-y-2">
                                        <div v-for="(verdict, sandbox) in analysisResult.virustotal.sandbox_verdicts"
                                            :key="sandbox" class="flex items-center gap-3">
                                            <span class="text-sm text-muted-foreground w-28 shrink-0">{{ sandbox
                                                }}</span>
                                            <span
                                                class="inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-medium border"
                                                :class="{
                                                    'bg-red-500/10 border-red-500/30 text-red-500': verdict.category === 'malicious',
                                                    'bg-orange-500/10 border-orange-500/30 text-orange-500': verdict.category === 'suspicious',
                                                    'bg-emerald-500/10 border-emerald-500/30 text-emerald-500': verdict.category === 'harmless',
                                                    'bg-muted/50 border-border/50 text-muted-foreground': !['malicious', 'suspicious', 'harmless'].includes(verdict.category)
                                                }">
                                                {{ verdict.category || verdict.verdict || 'unknown' }}
                                            </span>
                                        </div>
                                    </div>
                                    <div v-else class="flex items-center gap-3 py-2 text-muted-foreground">
                                        <Cpu class="w-5 h-5 text-muted-foreground/40" />
                                        <span class="text-sm">No sandbox data available</span>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- 3. Community Votes - Simple Inline Style -->
                        <div class="mt-4">
                            <p class="text-base font-semibold text-foreground mb-3">Community Votes</p>
                            <div class="flex items-center gap-4">
                                <div class="flex items-center gap-1.5">
                                    <CheckCircle class="w-4 h-4 text-emerald-500" />
                                    <span class="text-emerald-500 font-semibold text-lg">{{
                                        analysisResult.virustotal.raw_data?.attributes?.total_votes?.harmless || 0
                                        }}</span>
                                    <span class="text-sm text-muted-foreground">Harmless</span>
                                </div>
                                <div class="flex items-center gap-1.5">
                                    <XCircle class="w-4 h-4 text-red-500" />
                                    <span class="text-red-500 font-semibold text-lg">{{
                                        analysisResult.virustotal.raw_data?.attributes?.total_votes?.malicious || 0
                                        }}</span>
                                    <span class="text-sm text-muted-foreground">Malicious</span>
                                </div>
                            </div>
                        </div>

                        <!-- Footer -->
                        <div class="flex justify-end pt-6 border-t border-border/20 mt-6">
                            <a v-if="analysisResult.virustotal.sha256"
                                :href="`https://www.virustotal.com/gui/file/${analysisResult.virustotal.sha256}`"
                                target="_blank"
                                class="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-primary-foreground bg-primary hover:bg-primary/90 rounded-lg transition-colors shadow-lg">
                                <ExternalLink class="h-4 w-4" />
                                View on VirusTotal
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Hybrid Analysis Results -->
            <div v-if="analysisResult?.hybrid_analysis"
                class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl overflow-hidden">
                <div class="p-6 cursor-pointer hover:bg-muted/30 transition-colors"
                    @click="toggleSection('hybridanalysis')">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="p-2 bg-primary/10 rounded-lg">
                                <Shield class="h-5 w-5 text-primary" />
                            </div>
                            <div>
                                <h3 class="font-semibold text-lg">Hybrid Analysis</h3>
                                <p class="text-sm text-muted-foreground">Sandbox malware analysis</p>
                            </div>
                        </div>
                        <div class="flex items-center gap-3">
                            <Badge
                                v-if="analysisResult.hybrid_analysis.verdict && !analysisResult.hybrid_analysis.error"
                                :variant="analysisResult.hybrid_analysis.verdict === 'malicious' ? 'destructive' :
                                    analysisResult.hybrid_analysis.verdict === 'suspicious' ? 'secondary' : 'outline'"
                                class="text-sm px-3 py-1">
                                {{ analysisResult.hybrid_analysis.verdict }}
                            </Badge>
                            <component :is="expandedSections.hybridanalysis ? ChevronUp : ChevronDown"
                                class="h-5 w-5 text-muted-foreground" />
                        </div>
                    </div>
                </div>
                <div v-if="expandedSections.hybridanalysis" class="p-6 pt-0 border-t border-border/50">
                    <!-- Error State -->
                    <div v-if="analysisResult.hybrid_analysis.error"
                        class="mt-4 p-3 bg-yellow-50 dark:bg-yellow-950/20 rounded-lg border border-yellow-200 dark:border-yellow-900">
                        <div class="flex items-center gap-2 text-yellow-700 dark:text-yellow-400">
                            <AlertTriangle class="h-4 w-4" />
                            <span class="text-sm">{{ analysisResult.hybrid_analysis.error }}</span>
                        </div>
                    </div>

                    <!-- Not Found State -->
                    <div v-else-if="analysisResult.hybrid_analysis.verdict === 'not found'"
                        class="mt-4 p-6 bg-muted/30 rounded-xl text-center">
                        <Info class="h-10 w-10 text-muted-foreground mx-auto mb-3" />
                        <h4 class="font-medium text-foreground">Not Found in Sandbox Database</h4>
                        <p class="text-sm text-muted-foreground mt-1">
                            This file hasn't been analyzed by Hybrid Analysis sandbox yet.
                        </p>
                        <a v-if="analysisResult.hybrid_analysis.report_url"
                            :href="analysisResult.hybrid_analysis.report_url" target="_blank"
                            class="inline-flex items-center gap-2 mt-4 px-4 py-2 bg-primary/10 hover:bg-primary/20 text-primary rounded-lg transition-colors text-sm font-medium">
                            <ExternalLink class="h-4 w-4" />
                            Submit for Analysis
                        </a>
                    </div>

                    <!-- Results -->
                    <div v-else class="mt-4 space-y-4">
                        <!-- Threat Score & Verdict -->
                        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                            <div class="p-4 rounded-xl text-center" :class="{
                                'bg-red-50 dark:bg-red-950/20': analysisResult.hybrid_analysis.verdict === 'malicious',
                                'bg-yellow-50 dark:bg-yellow-950/20': analysisResult.hybrid_analysis.verdict === 'suspicious',
                                'bg-emerald-50 dark:bg-emerald-950/20': analysisResult.hybrid_analysis.verdict === 'no specific threat',
                                'bg-muted/50': !analysisResult.hybrid_analysis.verdict || analysisResult.hybrid_analysis.verdict === 'not found'
                            }">
                                <p class="text-xs text-muted-foreground mb-1">Verdict</p>
                                <p class="text-lg font-bold capitalize" :class="{
                                    'text-red-600': analysisResult.hybrid_analysis.verdict === 'malicious',
                                    'text-yellow-600': analysisResult.hybrid_analysis.verdict === 'suspicious',
                                    'text-emerald-600': analysisResult.hybrid_analysis.verdict === 'no specific threat',
                                    'text-muted-foreground': !analysisResult.hybrid_analysis.verdict || analysisResult.hybrid_analysis.verdict === 'not found'
                                }">
                                    {{ analysisResult.hybrid_analysis.verdict || 'Unknown' }}
                                </p>
                            </div>
                            <div v-if="analysisResult.hybrid_analysis.threat_score !== null && analysisResult.hybrid_analysis.threat_score !== undefined"
                                class="p-4 rounded-xl text-center" :class="{
                                    'bg-red-50 dark:bg-red-950/20': analysisResult.hybrid_analysis.threat_score >= 70,
                                    'bg-yellow-50 dark:bg-yellow-950/20': analysisResult.hybrid_analysis.threat_score >= 30 && analysisResult.hybrid_analysis.threat_score < 70,
                                    'bg-emerald-50 dark:bg-emerald-950/20': analysisResult.hybrid_analysis.threat_score < 30
                                }">
                                <p class="text-xs text-muted-foreground mb-1">Threat Score</p>
                                <p class="text-2xl font-bold" :class="{
                                    'text-red-600': analysisResult.hybrid_analysis.threat_score >= 70,
                                    'text-yellow-600': analysisResult.hybrid_analysis.threat_score >= 30 && analysisResult.hybrid_analysis.threat_score < 70,
                                    'text-emerald-600': analysisResult.hybrid_analysis.threat_score < 30
                                }">
                                    {{ analysisResult.hybrid_analysis.threat_score }}/100
                                </p>
                            </div>
                            <div v-if="analysisResult.hybrid_analysis.av_detect !== null && analysisResult.hybrid_analysis.av_detect !== undefined"
                                class="p-4 bg-muted/50 rounded-xl text-center">
                                <p class="text-xs text-muted-foreground mb-1">AV Detections</p>
                                <p class="text-2xl font-bold"
                                    :class="analysisResult.hybrid_analysis.av_detect > 0 ? 'text-red-600' : 'text-emerald-600'">
                                    {{ analysisResult.hybrid_analysis.av_detect }}
                                </p>
                            </div>
                            <div v-if="analysisResult.hybrid_analysis.file_type"
                                class="p-4 bg-muted/50 rounded-xl text-center cursor-pointer hover:bg-muted/70 transition-colors"
                                @click="expandedSections.haFileType = !expandedSections.haFileType">
                                <p class="text-xs text-muted-foreground mb-1">File Type <span class="text-[10px]">(click
                                        to {{ expandedSections.haFileType ? 'collapse' : 'expand'
                                        }})</span></p>
                                <p class="text-sm font-medium break-words">
                                    {{ expandedSections.haFileType
                                        ? analysisResult.hybrid_analysis.file_type
                                        : (analysisResult.hybrid_analysis.file_type.length > 15
                                            ? analysisResult.hybrid_analysis.file_type.substring(0, 15) + '...'
                                            : analysisResult.hybrid_analysis.file_type) }}
                                </p>
                            </div>
                        </div>

                        <!-- Anti-Virus Results -->
                        <div class="mt-8 mb-8">
                            <div class="flex items-center justify-between mb-5">
                                <h4 class="text-base font-semibold flex items-center gap-2.5">
                                    <div class="p-1.5 bg-gradient-to-br from-primary/20 to-blue-500/20 rounded-lg">
                                        <Shield class="w-4 h-4 text-primary" />
                                    </div>
                                    Anti-Virus Results
                                </h4>
                                <span v-if="analysisResult.hybrid_analysis.av_detect > 0"
                                    class="px-3 py-1 rounded-full text-xs font-semibold bg-gradient-to-r from-red-500/20 to-orange-500/20 text-red-500 border border-red-500/20">
                                    {{ analysisResult.hybrid_analysis.av_detect }} detection{{
                                        analysisResult.hybrid_analysis.av_detect !== 1 ? 's' : '' }}
                                </span>
                            </div>

                            <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                                <!-- CrowdStrike Falcon Card -->
                                <div
                                    class="group relative bg-gradient-to-br from-card via-card to-primary/5 border border-border/60 rounded-2xl p-5 flex flex-col overflow-hidden hover:border-primary/40 hover:shadow-xl hover:shadow-primary/10 transition-all duration-300">
                                    <!-- Decorative gradient -->
                                    <div
                                        class="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-primary/10 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-500">
                                    </div>

                                    <div class="flex items-center gap-3.5 mb-5 relative z-10">
                                        <div
                                            class="p-3 bg-gradient-to-br from-primary/20 to-primary/10 rounded-xl border border-primary/20 shadow-sm">
                                            <Activity class="w-6 h-6 text-primary" />
                                        </div>
                                        <div class="flex-1">
                                            <a v-if="analysisResult.hybrid_analysis.report_url"
                                                :href="analysisResult.hybrid_analysis.report_url" target="_blank"
                                                class="font-semibold text-lg hover:text-primary transition-colors flex items-center gap-2 group/link">
                                                CrowdStrike Falcon
                                                <ExternalLink
                                                    class="w-4 h-4 text-muted-foreground opacity-0 group-hover/link:opacity-100 transition-opacity" />
                                            </a>
                                            <p v-else class="font-semibold text-lg">CrowdStrike Falcon
                                            </p>
                                            <p class="text-sm text-muted-foreground">Static Analysis &
                                                ML</p>
                                        </div>
                                    </div>

                                    <!-- Threat Score Progress -->
                                    <div v-if="analysisResult.hybrid_analysis.threat_score !== null && analysisResult.hybrid_analysis.threat_score !== undefined"
                                        class="mb-5 relative z-10">
                                        <div class="flex justify-between items-center text-sm mb-2">
                                            <span class="text-muted-foreground font-medium">Threat
                                                Score</span>
                                            <span class="font-bold text-base" :class="{
                                                'text-red-500': analysisResult.hybrid_analysis.threat_score >= 70,
                                                'text-orange-500': analysisResult.hybrid_analysis.threat_score >= 30 && analysisResult.hybrid_analysis.threat_score < 70,
                                                'text-emerald-500': analysisResult.hybrid_analysis.threat_score < 30
                                            }">{{ analysisResult.hybrid_analysis.threat_score
                                            }}%</span>
                                        </div>
                                        <div class="w-full h-2.5 rounded-full overflow-hidden bg-muted/40 shadow-inner">
                                            <div class="h-full rounded-full transition-all duration-700 ease-out shadow-sm"
                                                :class="{
                                                    'bg-gradient-to-r from-red-500 via-red-500 to-red-600': analysisResult.hybrid_analysis.threat_score >= 70,
                                                    'bg-gradient-to-r from-orange-400 via-orange-500 to-orange-600': analysisResult.hybrid_analysis.threat_score >= 30 && analysisResult.hybrid_analysis.threat_score < 70,
                                                    'bg-gradient-to-r from-emerald-400 via-emerald-500 to-emerald-600': analysisResult.hybrid_analysis.threat_score < 30
                                                }"
                                                :style="{ width: `${analysisResult.hybrid_analysis.threat_score}%` }">
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Verdict Display -->
                                    <div class="flex-1 flex flex-col items-center justify-center py-5 relative z-10">
                                        <div v-if="analysisResult.hybrid_analysis.threat_score !== null && analysisResult.hybrid_analysis.threat_score !== undefined"
                                            class="text-center">
                                            <div class="w-20 h-20 mx-auto mb-4 rounded-full flex items-center justify-center border-[3px] shadow-lg transition-transform duration-300 group-hover:scale-105"
                                                :class="{
                                                    'bg-gradient-to-br from-red-500/20 to-red-600/10 border-red-500/50 shadow-red-500/20': analysisResult.hybrid_analysis.threat_score >= 70,
                                                    'bg-gradient-to-br from-orange-500/20 to-orange-600/10 border-orange-500/50 shadow-orange-500/20': analysisResult.hybrid_analysis.threat_score >= 30 && analysisResult.hybrid_analysis.threat_score < 70,
                                                    'bg-gradient-to-br from-emerald-500/20 to-emerald-600/10 border-emerald-500/50 shadow-emerald-500/20': analysisResult.hybrid_analysis.threat_score < 30
                                                }">
                                                <AlertTriangle v-if="analysisResult.hybrid_analysis.threat_score >= 70"
                                                    class="w-10 h-10 text-red-500" />
                                                <AlertOctagon
                                                    v-else-if="analysisResult.hybrid_analysis.threat_score >= 30"
                                                    class="w-10 h-10 text-orange-500" />
                                                <CheckCircle v-else class="w-10 h-10 text-emerald-500" />
                                            </div>
                                            <p class="text-2xl font-bold capitalize tracking-tight" :class="{
                                                'text-red-500': analysisResult.hybrid_analysis.threat_score >= 70,
                                                'text-orange-500': analysisResult.hybrid_analysis.threat_score >= 30 && analysisResult.hybrid_analysis.threat_score < 70,
                                                'text-emerald-500': analysisResult.hybrid_analysis.threat_score < 30
                                            }">
                                                {{ analysisResult.hybrid_analysis.verdict ||
                                                    (analysisResult.hybrid_analysis.threat_score >= 50 ?
                                                        'Malicious' :
                                                        'Clean') }}
                                                <span class="text-base font-semibold opacity-70">({{
                                                    analysisResult.hybrid_analysis.threat_score
                                                }}%)</span>
                                            </p>
                                        </div>
                                        <div v-else class="text-center">
                                            <div
                                                class="w-20 h-20 mx-auto mb-4 rounded-full bg-muted/30 flex items-center justify-center border-2 border-border/50">
                                                <Info class="w-9 h-9 text-muted-foreground/50" />
                                            </div>
                                            <p class="text-lg font-medium text-muted-foreground">No
                                                score available
                                            </p>
                                        </div>
                                    </div>

                                    <div class="mt-auto pt-4 border-t border-border/40 relative z-10">
                                        <p
                                            class="text-xs text-muted-foreground/60 text-center flex items-center justify-center gap-2">
                                            <XCircle class="w-4 h-4" />
                                            No Additional Data Available
                                        </p>
                                    </div>
                                </div>

                                <!-- MetaDefender Card -->
                                <div
                                    class="group relative bg-gradient-to-br from-card via-card to-blue-500/5 border border-border/60 rounded-2xl p-5 flex flex-col overflow-hidden hover:border-blue-500/40 hover:shadow-xl hover:shadow-blue-500/10 transition-all duration-300">
                                    <!-- Decorative gradient -->
                                    <div
                                        class="absolute top-0 right-0 w-32 h-32 bg-gradient-to-bl from-blue-500/10 to-transparent rounded-bl-full opacity-0 group-hover:opacity-100 transition-opacity duration-500">
                                    </div>

                                    <div class="flex items-center gap-3.5 mb-5 relative z-10">
                                        <div
                                            class="p-3 bg-gradient-to-br from-blue-500/20 to-blue-600/10 rounded-xl border border-blue-500/20 shadow-sm">
                                            <Search class="w-6 h-6 text-blue-500" />
                                        </div>
                                        <div class="flex-1">
                                            <a v-if="analysisResult.hybrid_analysis.report_url"
                                                :href="analysisResult.hybrid_analysis.report_url" target="_blank"
                                                class="font-semibold text-lg hover:text-blue-500 transition-colors flex items-center gap-2 group/link">
                                                MetaDefender
                                                <ExternalLink
                                                    class="w-4 h-4 text-muted-foreground opacity-0 group-hover/link:opacity-100 transition-opacity" />
                                            </a>
                                            <p v-else class="font-semibold text-lg">MetaDefender</p>
                                            <p class="text-sm text-muted-foreground">Multi Scan Analysis
                                            </p>
                                        </div>
                                    </div>

                                    <!-- Detection Progress -->
                                    <div v-if="analysisResult.hybrid_analysis.av_detect !== null && analysisResult.hybrid_analysis.av_detect !== undefined"
                                        class="mb-5 relative z-10">
                                        <div class="flex justify-between items-center text-sm mb-2">
                                            <span class="text-muted-foreground font-medium">AV
                                                Detections</span>
                                            <span class="font-bold text-base"
                                                :class="analysisResult.hybrid_analysis.av_detect > 0 ? 'text-red-500' : 'text-emerald-500'">
                                                {{ analysisResult.hybrid_analysis.av_detect }}/27
                                                engines
                                            </span>
                                        </div>
                                        <div class="w-full h-2.5 rounded-full overflow-hidden bg-muted/40 shadow-inner">
                                            <div class="h-full rounded-full transition-all duration-700 ease-out shadow-sm"
                                                :class="analysisResult.hybrid_analysis.av_detect > 0 ? 'bg-gradient-to-r from-red-500 via-red-500 to-red-600' : 'bg-gradient-to-r from-emerald-400 via-emerald-500 to-emerald-600'"
                                                :style="{ width: `${Math.min((analysisResult.hybrid_analysis.av_detect / 27) * 100, 100)}%` }">
                                            </div>
                                        </div>
                                    </div>

                                    <!-- Verdict Display -->
                                    <div class="flex-1 flex flex-col items-center justify-center py-5 relative z-10">
                                        <div v-if="analysisResult.hybrid_analysis.av_detect !== null && analysisResult.hybrid_analysis.av_detect !== undefined"
                                            class="text-center">
                                            <div class="w-20 h-20 mx-auto mb-4 rounded-full flex items-center justify-center border-[3px] shadow-lg transition-transform duration-300 group-hover:scale-105"
                                                :class="analysisResult.hybrid_analysis.av_detect > 0
                                                    ? 'bg-gradient-to-br from-red-500/20 to-red-600/10 border-red-500/50 shadow-red-500/20'
                                                    : 'bg-gradient-to-br from-emerald-500/20 to-emerald-600/10 border-emerald-500/50 shadow-emerald-500/20'">
                                                <AlertTriangle v-if="analysisResult.hybrid_analysis.av_detect > 0"
                                                    class="w-10 h-10 text-red-500" />
                                                <CheckCircle v-else class="w-10 h-10 text-emerald-500" />
                                            </div>
                                            <p class="text-2xl font-bold tracking-tight"
                                                :class="analysisResult.hybrid_analysis.av_detect > 0 ? 'text-red-500' : 'text-emerald-500'">
                                                {{ analysisResult.hybrid_analysis.av_detect > 0 ?
                                                    'Malicious' :
                                                    'Clean'
                                                }}
                                                <span class="text-base font-semibold opacity-70">({{
                                                    analysisResult.hybrid_analysis.av_detect
                                                }}/27)</span>
                                            </p>
                                        </div>
                                        <!-- No av_detect but we have HA results - show as clean (0 detections) -->
                                        <div v-else-if="analysisResult.hybrid_analysis.verdict && analysisResult.hybrid_analysis.verdict !== 'not found'"
                                            class="text-center">
                                            <div
                                                class="w-20 h-20 mx-auto mb-4 rounded-full bg-gradient-to-br from-emerald-500/20 to-emerald-600/10 flex items-center justify-center border-[3px] border-emerald-500/50 shadow-lg shadow-emerald-500/20 transition-transform duration-300 group-hover:scale-105">
                                                <CheckCircle class="w-10 h-10 text-emerald-500" />
                                            </div>
                                            <p class="text-2xl font-bold tracking-tight text-emerald-500">
                                                Clean
                                                <span class="text-base font-semibold opacity-70">(0/27)</span>
                                            </p>
                                        </div>
                                        <!-- No data at all -->
                                        <div v-else class="text-center">
                                            <div
                                                class="w-20 h-20 mx-auto mb-4 rounded-full bg-muted/30 flex items-center justify-center border-2 border-border/50">
                                                <Info class="w-9 h-9 text-muted-foreground/50" />
                                            </div>
                                            <p class="text-lg font-medium text-muted-foreground">No AV
                                                data</p>
                                        </div>
                                    </div>

                                    <div class="mt-auto pt-4 border-t border-border/40 relative z-10">
                                        <p v-if="!analysisResult.hybrid_analysis.report_url"
                                            class="text-xs text-muted-foreground/60 text-center flex items-center justify-center gap-2">
                                            <XCircle class="w-4 h-4" />
                                            No Additional Data Available
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Malware Family -->
                        <div v-if="analysisResult.hybrid_analysis.vx_family"
                            class="p-4 bg-red-50 dark:bg-red-950/20 rounded-xl border border-red-200 dark:border-red-900">
                            <div class="flex items-center gap-2">
                                <AlertOctagon class="h-5 w-5 text-red-500" />
                                <span class="font-semibold text-red-700 dark:text-red-400">Malware
                                    Family:</span>
                                <span class="text-red-600 dark:text-red-300 font-mono">{{
                                    analysisResult.hybrid_analysis.vx_family }}</span>
                            </div>
                        </div>

                        <!-- Tags -->
                        <div v-if="analysisResult.hybrid_analysis.tags?.length" class="space-y-2">
                            <div class="flex items-center gap-2 text-sm text-muted-foreground">
                                <Tag class="h-4 w-4" />
                                <span class="font-medium">Tags</span>
                            </div>
                            <div class="flex flex-wrap gap-2">
                                <Badge v-for="tag in analysisResult.hybrid_analysis.tags.slice(0, 15)" :key="tag"
                                    variant="outline" class="text-xs">
                                    {{ tag }}
                                </Badge>
                                <Badge v-if="analysisResult.hybrid_analysis.tags.length > 15" variant="secondary"
                                    class="text-xs">
                                    +{{ analysisResult.hybrid_analysis.tags.length - 15 }} more
                                </Badge>
                            </div>
                        </div>

                        <!-- Classification Tags -->
                        <div v-if="analysisResult.hybrid_analysis.classification_tags?.length" class="space-y-2">
                            <div class="flex items-center gap-2 text-sm text-muted-foreground">
                                <Target class="h-4 w-4" />
                                <span class="font-medium">Classification</span>
                            </div>
                            <div class="flex flex-wrap gap-2">
                                <Badge v-for="tag in analysisResult.hybrid_analysis.classification_tags.slice(0, 10)"
                                    :key="tag" variant="destructive" class="text-xs">
                                    {{ tag }}
                                </Badge>
                            </div>
                        </div>

                        <!-- MITRE ATT&CK -->
                        <div v-if="analysisResult.hybrid_analysis.mitre_attcks?.length"
                            class="p-4 bg-orange-50 dark:bg-orange-950/20 rounded-xl border border-orange-200 dark:border-orange-900">
                            <div class="flex items-center gap-2 mb-3">
                                <Target class="h-5 w-5 text-orange-600" />
                                <span class="font-semibold text-orange-700 dark:text-orange-400">MITRE
                                    ATT&CK
                                    Techniques</span>
                            </div>
                            <div class="flex flex-wrap gap-2">
                                <Badge v-for="technique in analysisResult.hybrid_analysis.mitre_attcks" :key="technique"
                                    variant="outline"
                                    class="text-xs font-mono bg-orange-100 dark:bg-orange-900/30 border-orange-300 dark:border-orange-700">
                                    {{ technique }}
                                </Badge>
                            </div>
                        </div>

                        <!-- Behavioral Analysis -->
                        <div v-if="analysisResult.hybrid_analysis.total_processes || analysisResult.hybrid_analysis.total_signatures || analysisResult.hybrid_analysis.total_network_connections"
                            class="grid grid-cols-3 gap-4">
                            <div v-if="analysisResult.hybrid_analysis.total_processes !== null && analysisResult.hybrid_analysis.total_processes !== undefined"
                                class="p-3 bg-muted/50 rounded-lg text-center">
                                <Cpu class="h-5 w-5 text-muted-foreground mx-auto mb-1" />
                                <p class="text-lg font-bold">{{
                                    analysisResult.hybrid_analysis.total_processes }}
                                </p>
                                <p class="text-xs text-muted-foreground">Processes</p>
                            </div>
                            <div v-if="analysisResult.hybrid_analysis.total_signatures !== null && analysisResult.hybrid_analysis.total_signatures !== undefined"
                                class="p-3 bg-muted/50 rounded-lg text-center">
                                <Activity class="h-5 w-5 text-muted-foreground mx-auto mb-1" />
                                <p class="text-lg font-bold"
                                    :class="analysisResult.hybrid_analysis.total_signatures > 0 ? 'text-orange-600' : ''">
                                    {{ analysisResult.hybrid_analysis.total_signatures }}
                                </p>
                                <p class="text-xs text-muted-foreground">Signatures</p>
                            </div>
                            <div v-if="analysisResult.hybrid_analysis.total_network_connections !== null && analysisResult.hybrid_analysis.total_network_connections !== undefined"
                                class="p-3 bg-muted/50 rounded-lg text-center">
                                <Network class="h-5 w-5 text-muted-foreground mx-auto mb-1" />
                                <p class="text-lg font-bold">{{
                                    analysisResult.hybrid_analysis.total_network_connections
                                }}</p>
                                <p class="text-xs text-muted-foreground">Connections</p>
                            </div>
                        </div>

                        <!-- Network Indicators -->
                        <div v-if="analysisResult.hybrid_analysis.domains?.length || analysisResult.hybrid_analysis.hosts?.length"
                            class="p-4 bg-muted/30 rounded-xl space-y-3">
                            <div class="flex items-center gap-2 text-sm font-medium">
                                <Globe class="h-4 w-4 text-muted-foreground" />
                                <span>Network Indicators</span>
                            </div>
                            <!-- Domains -->
                            <div v-if="analysisResult.hybrid_analysis.domains?.length" class="space-y-1">
                                <p class="text-xs text-muted-foreground">Domains contacted ({{
                                    analysisResult.hybrid_analysis.domains.length }})</p>
                                <div class="flex flex-wrap gap-1.5">
                                    <span v-for="domain in analysisResult.hybrid_analysis.domains.slice(0, 10)"
                                        :key="domain"
                                        class="px-2 py-0.5 bg-background rounded text-xs font-mono border">
                                        {{ domain }}
                                    </span>
                                    <span v-if="analysisResult.hybrid_analysis.domains.length > 10"
                                        class="text-xs text-muted-foreground self-center">
                                        +{{ analysisResult.hybrid_analysis.domains.length - 10 }} more
                                    </span>
                                </div>
                            </div>
                            <!-- Hosts/IPs -->
                            <div v-if="analysisResult.hybrid_analysis.hosts?.length" class="space-y-1">
                                <p class="text-xs text-muted-foreground">Hosts/IPs contacted ({{
                                    analysisResult.hybrid_analysis.hosts.length }})</p>
                                <div class="flex flex-wrap gap-1.5">
                                    <span v-for="host in analysisResult.hybrid_analysis.hosts.slice(0, 10)" :key="host"
                                        class="px-2 py-0.5 bg-background rounded text-xs font-mono border">
                                        {{ host }}
                                    </span>
                                    <span v-if="analysisResult.hybrid_analysis.hosts.length > 10"
                                        class="text-xs text-muted-foreground self-center">
                                        +{{ analysisResult.hybrid_analysis.hosts.length - 10 }} more
                                    </span>
                                </div>
                            </div>
                        </div>

                        <!-- Analysis Info & Report Link -->
                        <div class="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-border/50">
                            <div class="flex flex-col gap-1 text-sm text-muted-foreground">
                                <div v-if="analysisResult.hybrid_analysis.submit_name" class="flex items-center gap-2">
                                    <span class="font-medium">Submitted as:</span>
                                    <span class="font-mono text-xs">{{
                                        analysisResult.hybrid_analysis.submit_name
                                    }}</span>
                                </div>
                                <div v-if="analysisResult.hybrid_analysis.environment_description"
                                    class="flex items-center gap-2">
                                    <span class="font-medium">Environment:</span>
                                    <span>{{ analysisResult.hybrid_analysis.environment_description
                                    }}</span>
                                </div>
                                <div v-if="analysisResult.hybrid_analysis.analysis_start_time"
                                    class="flex items-center gap-2">
                                    <Clock class="h-3 w-3" />
                                    <span>Analyzed: {{
                                        analysisResult.hybrid_analysis.analysis_start_time }}</span>
                                </div>
                            </div>
                            <a v-if="analysisResult.hybrid_analysis.report_url"
                                :href="analysisResult.hybrid_analysis.report_url" target="_blank"
                                class="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-primary-foreground bg-primary hover:bg-primary/90 rounded-lg transition-colors shadow-lg">
                                <ExternalLink class="h-4 w-4" />
                                View On Hybrid Analysis
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Not Found Message -->
            <div v-if="overallRisk?.level === 'unknown' && analysisResult?.virustotal?.error?.includes('404')"
                class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl p-8 text-center">
                <Info class="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <h3 class="text-lg font-semibold">File Not Found in Database</h3>
                <p class="text-muted-foreground mt-2">
                    This file hash was not found in VirusTotal's database.
                    This could mean the file has never been submitted for analysis.
                </p>
            </div>

            <!-- Raw Analysis Data -->
            <div class="bg-card/50 backdrop-blur-xl border border-border/50 shadow-lg rounded-2xl overflow-hidden">
                <div class="p-6 cursor-pointer hover:bg-muted/30 transition-colors" @click="toggleSection('raw')">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-3">
                            <div class="p-2 bg-muted rounded-lg">
                                <Activity class="h-5 w-5 text-muted-foreground" />
                            </div>
                            <div>
                                <h3 class="font-semibold text-lg">Raw Analysis Data</h3>
                                <p class="text-sm text-muted-foreground">Complete API response</p>
                            </div>
                        </div>
                        <component :is="expandedSections.raw ? ChevronUp : ChevronDown"
                            class="h-5 w-5 text-muted-foreground" />
                    </div>
                </div>
                <div v-if="expandedSections.raw" class="p-6 pt-0 border-t border-border/50">
                    <div
                        class="border border-border/40 rounded-xl p-4 overflow-auto max-h-[500px] mt-4 text-sm font-mono">
                        <!-- JSON Tree View - Same design as MDM View -->
                        <template v-for="(value, key) in analysisResult" :key="`raw.${key}`">
                            <div class="py-0.5">
                                <!-- Object/Array - Collapsible -->
                                <template v-if="value !== null && typeof value === 'object'">
                                    <button @click="toggleJsonNode(`raw.${key}`)"
                                        class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                        <ChevronRight
                                            class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                            :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}`) }" />
                                        <span class="text-foreground">{{ key }}:</span>
                                        <span class="text-muted-foreground">{{ getItemLabel(value)
                                        }}</span>
                                    </button>
                                    <!-- Level 2 -->
                                    <div v-if="isJsonNodeExpanded(`raw.${key}`)"
                                        class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                        <template v-for="(val2, key2) in (value as object)" :key="`raw.${key}.${key2}`">
                                            <div class="py-0.5">
                                                <template v-if="val2 !== null && typeof val2 === 'object'">
                                                    <button @click="toggleJsonNode(`raw.${key}.${key2}`)"
                                                        class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                                        <ChevronRight
                                                            class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                                            :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}.${key2}`) }" />
                                                        <span class="text-foreground">{{ key2 }}:</span>
                                                        <span class="text-muted-foreground">{{
                                                            getItemLabel(val2)
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
                                                                        <span class="text-foreground">{{
                                                                            key3
                                                                        }}:</span>
                                                                        <span class="text-muted-foreground">{{
                                                                            getItemLabel(val3) }}</span>
                                                                    </button>
                                                                    <!-- Level 4 -->
                                                                    <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}.${key3}`)"
                                                                        class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                                                        <template
                                                                            v-for="(val4, key4) in (val3 as object)"
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
                                                                                        <span class="text-foreground">{{
                                                                                            key4 }}:</span>
                                                                                        <span
                                                                                            class="text-muted-foreground">{{
                                                                                                getItemLabel(val4) }}</span>
                                                                                    </button>
                                                                                    <!-- Level 5 -->
                                                                                    <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}.${key3}.${key4}`)"
                                                                                        class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                                                                        <template
                                                                                            v-for="(val5, key5) in (val4 as object)"
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
                                                                                                        <span
                                                                                                            class="text-foreground">{{
                                                                                                                key5
                                                                                                            }}:</span>
                                                                                                        <span
                                                                                                            class="text-muted-foreground">{{
                                                                                                                getItemLabel(val5)
                                                                                                            }}</span>
                                                                                                    </button>
                                                                                                    <!-- Level 6+ - Show as JSON -->
                                                                                                    <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}.${key3}.${key4}.${key5}`)"
                                                                                                        class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                                                                                        <pre
                                                                                                            class="text-foreground whitespace-pre-wrap break-words text-xs">{{ prettyJson(val5) }}</pre>
                                                                                                    </div>
                                                                                                </template>
                                                                                                <template v-else>
                                                                                                    <div
                                                                                                        class="flex items-start gap-1.5 pl-4">
                                                                                                        <span
                                                                                                            class="text-foreground shrink-0">{{
                                                                                                                key5
                                                                                                            }}:</span>
                                                                                                        <span
                                                                                                            class="text-muted-foreground ml-1 break-all">{{
                                                                                                                val5 ===
                                                                                                                    null ?
                                                                                                                    'null' :
                                                                                                                    val5
                                                                                                            }}</span>
                                                                                                    </div>
                                                                                                </template>
                                                                                            </div>
                                                                                        </template>
                                                                                    </div>
                                                                                </template>
                                                                                <template v-else>
                                                                                    <div
                                                                                        class="flex items-start gap-1.5 pl-4">
                                                                                        <span
                                                                                            class="text-foreground shrink-0">{{
                                                                                                key4 }}:</span>
                                                                                        <span
                                                                                            class="text-muted-foreground ml-1 break-all">{{
                                                                                                val4 === null ? 'null' :
                                                                                                    val4 }}</span>
                                                                                    </div>
                                                                                </template>
                                                                            </div>
                                                                        </template>
                                                                    </div>
                                                                </template>
                                                                <template v-else>
                                                                    <div class="flex items-start gap-1.5 pl-4">
                                                                        <span class="text-foreground shrink-0">{{
                                                                            key3
                                                                        }}:</span>
                                                                        <span
                                                                            class="text-muted-foreground ml-1 break-all">{{
                                                                                val3 === null ? 'null' :
                                                                                    val3 }}</span>
                                                                    </div>
                                                                </template>
                                                            </div>
                                                        </template>
                                                    </div>
                                                </template>
                                                <template v-else>
                                                    <div class="flex items-start gap-1.5 pl-4">
                                                        <span class="text-foreground shrink-0">{{ key2
                                                        }}:</span>
                                                        <span class="text-muted-foreground ml-1 break-all">{{
                                                            val2
                                                                ===
                                                                null ? 'null' : val2 }}</span>
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
                                        <span class="text-muted-foreground ml-1 break-all">{{ value ===
                                            null ?
                                            'null' :
                                            value }}</span>
                                    </div>
                                </template>
                            </div>
                        </template>
                    </div>
                </div>
            </div>
        </div>
    </main>
</template>
