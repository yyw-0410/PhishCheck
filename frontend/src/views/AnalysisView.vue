<script setup lang="ts">
import { computed, ref, watch, onUnmounted, provide } from 'vue'
import DOMPurify from 'dompurify'
import {
  UploadCloud,
  FileText,
  ShieldAlert,
  ShieldCheck,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Bot,
  Mail,
  Loader2,
  Globe,
  Lightbulb,
  Server,
  Wifi,
  Code,
  FileCode,
  Database,
  Download,
  KeyRound,
  ArrowRight,
  Eye,
  Trash2,
  Plus,
  Monitor,
  RefreshCw,
} from 'lucide-vue-next'

import type { UrlscanSubmission } from '@/types/analysis'

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import JsonTreeNode from '@/components/ui/JsonTreeNode.vue'

import { useAnalysisState } from '@/hooks/useAnalysisState'
import { useSublimeInsights } from '@/hooks/useSublimeInsights'
import { useThreatIntel } from '@/hooks/useThreatIntel'
import { useParsedEmail } from '@/hooks/useParsedEmail'
import { isPlaceholderScreenshot, isVerdictPending, getLiveshotUrl } from '@/utils/screenshotUtils'

const {
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
  submit,
  triggerFileDialog,
  clearFile,
  aiRecommendation,
  aiRecommendationLoading,
  // URL scanning features
  hasMoreUrlsToScan,
  skippedUrlCount,
  scanMoreUrls,
  scanAllUrls,
  scanningMoreUrls,
} = useAnalysisState()

const {
  attackScoreSummary,
  displayedUiInsightHits,
  displayedUiRuleHits,
  filteredUiInsightHits,
  insightCounts,
  insightSeverityFilter,
  ruleSummary,
  // showAllInsights,
  // showAllRules,
} = useSublimeInsights(analysisResult)

const {
  copiedHashes,
  copiedTargets,
  copyHash,
  copyTarget,
  getVtResultForFile,
  openVtForFile,
  urlscanKey,
  urlscanVerdict,
  urlscanSubmissions,
  vtByType,
  vtFlaggedItems,
  virusTotalSummaries,
  ipqsResults,
  hybridAnalysisResults,
} = useThreatIntel(analysisResult)

const { attachmentSummary, senderDetails, emailContent, rawTextBody, rawHtmlBody, rawEmlContent, mdmData } = useParsedEmail(analysisResult)

// Tab state for Message Content views
const activeMessageTab = ref<'user' | 'text' | 'html' | 'eml' | 'mdm'>('user')

// Sanitized HTML for safe rendering in User View (display only, no clickable links)
// Security: Links disabled, scripts blocked, but images allowed for better viewing
const sanitizedHtml = computed(() => {
  if (!rawHtmlBody.value) return ''
  // Use DOMPurify for proper XSS protection
  const clean = DOMPurify.sanitize(rawHtmlBody.value, {
    ALLOWED_TAGS: ['p', 'br', 'div', 'span', 'b', 'i', 'u', 'strong', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
      'ul', 'ol', 'li', 'table', 'thead', 'tbody', 'tr', 'td', 'th', 'blockquote', 'pre', 'code', 'hr', 'img', 'center', 'font'],
    ALLOWED_ATTR: ['class', 'alt', 'width', 'height', 'colspan', 'rowspan', 'align', 'valign', 'bgcolor', 'color', 'size', 'src', 'style'],
    // Block dangerous attributes - allow src for images
    FORBID_ATTR: ['href', 'onclick', 'onerror', 'onload', 'onmouseover', 'action'],
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'a', 'link', 'meta', 'base'],
  })
  return clean
})

// Summary for IPQS IP reputation
const ipqsSummary = computed(() => {
  const results = ipqsResults.value || []
  if (!results.length) return { total: 0, flagged: 0, vpn: 0, proxy: 0, tor: 0 }
  let flagged = 0, vpn = 0, proxy = 0, tor = 0
  for (const r of results) {
    if ((r.fraud_score ?? 0) >= 75 || r.is_vpn || r.is_proxy || r.is_tor || r.recent_abuse) flagged++
    if (r.is_vpn) vpn++
    if (r.is_proxy) proxy++
    if (r.is_tor) tor++
  }
  return { total: results.length, flagged, vpn, proxy, tor }
})

// Summary for Hybrid Analysis file sandbox
const hybridAnalysisSummary = computed(() => {
  const results = hybridAnalysisResults.value || []
  if (!results.length) return { total: 0, malicious: 0, suspicious: 0 }
  let malicious = 0, suspicious = 0
  for (const r of results) {
    const verdict = (r.verdict || '').toLowerCase()
    if (verdict === 'malicious') malicious++
    else if (verdict === 'suspicious') suspicious++
  }
  return { total: results.length, malicious, suspicious }
})

// Threat Intel Alerts - detect when tools disagree (e.g., Sublime flags but others don't)
const threatIntelAlerts = computed(() => {
  const alerts: { url: string; sublimeLabel: string; urlscanVerdict: string; vtDetections: number }[] = []
  const scans = urlscanSubmissions.value || []

  for (const scan of scans) {
    const sublimeLabel = (scan.ml_link?.label || '').toLowerCase()
    const urlscanVerd = (scan.verdict || '').toLowerCase()

    // Check if Sublime ML flagged it but URLscan didn't
    const sublimeFlagged = sublimeLabel === 'phishing' || sublimeLabel === 'malicious' || sublimeLabel === 'suspicious'
    const urlscanClean = urlscanVerd === 'benign' || urlscanVerd === ''

    if (sublimeFlagged && urlscanClean) {
      alerts.push({
        url: scan.url || 'Unknown URL',
        sublimeLabel: sublimeLabel,
        urlscanVerdict: urlscanVerd || 'pending',
        vtDetections: 0 // TODO: cross-reference with VT results
      })
    }
  }
  return alerts
})

// Per-tool breakdown for Link Analysis
const linkAnalysisBreakdown = computed(() => {
  const scans = urlscanSubmissions.value || []
  let urlscanFlagged = 0, sublimeMlFlagged = 0, vtFlagged = 0
  // Track domains already counted to avoid duplicates (multiple URLs from same domain)
  const countedDomains = new Set<string>()

  for (const scan of scans) {
    const urlscanVerd = (scan.verdict || '').toLowerCase()
    const sublimeLabel = (scan.ml_link?.label || '').toLowerCase()

    if (urlscanVerd === 'malicious' || urlscanVerd === 'suspicious') urlscanFlagged++
    if (sublimeLabel === 'phishing' || sublimeLabel === 'malicious' || sublimeLabel === 'suspicious') sublimeMlFlagged++

    // Check VirusTotal result for this URL
    // First try exact URL match, then fall back to domain match
    if (scan.url) {
      // Check for exact URL match first
      const urlVtResult = virusTotalSummaries.value.find(
        s => s.indicator_type === 'url' && s.indicator === scan.url
      )
      if (urlVtResult && (urlVtResult.verdict === 'Malicious' || urlVtResult.verdict === 'Suspicious')) {
        vtFlagged++
      } else {
        // Fall back to domain match
        try {
          const domain = new URL(scan.url).hostname.replace(/^www\./, '').toLowerCase()
          // Only count each domain once even if multiple URLs use the same domain
          if (!countedDomains.has(domain)) {
            const vtResult = virusTotalSummaries.value.find(
              s => s.indicator_type === 'domain' && s.indicator.toLowerCase() === domain
            )
            if (vtResult && (vtResult.verdict === 'Malicious' || vtResult.verdict === 'Suspicious')) {
              vtFlagged++
            }
            countedDomains.add(domain)
          }
        } catch {
          // Invalid URL, skip
        }
      }
    }
  }

  return {
    urlscan: urlscanFlagged,
    sublimeMl: sublimeMlFlagged,
    virustotal: vtFlagged,
    total: scans.length || vtByType.value?.urlCount || 0
  }
})

// Per-tool breakdown for File Analysis
const fileAnalysisBreakdown = computed(() => {
  const vtFlagged = (vtByType.value?.fileMalicious ?? 0) + (vtByType.value?.fileSuspicious ?? 0)
  const haFlagged = hybridAnalysisSummary.value.malicious + hybridAnalysisSummary.value.suspicious
  const total = attachmentSummary.value?.total ?? 0

  return {
    virustotal: vtFlagged,
    hybridAnalysis: haFlagged,
    total
  }
})

// Download EML file
const downloadEml = () => {
  if (!rawEmlContent.value) return
  const blob = new Blob([rawEmlContent.value], { type: 'message/rfc822' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${emailContent.value?.subject || 'email'}.eml`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// Scroll to attachments section
const scrollToAttachments = () => {
  const attachmentsSection = document.getElementById('attachments-section')
  if (attachmentsSection) {
    attachmentsSection.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }
}

// Filtered analysis result without raw_eml (shown in EML View tab instead)
const filteredAnalysisResult = computed(() => {
  if (!analysisResult.value) return null
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { raw_eml, ...rest } = analysisResult.value as Record<string, unknown>
  return rest
})

// JSON Tree View for Raw Analysis Data
const rawDataExpanded = ref(false)
const jsonExpandedNodes = ref<Set<string>>(new Set())
provide('jsonExpandedNodes', jsonExpandedNodes)

// Reset JSON tree state when new analysis result comes in
watch(() => analysisResult.value, () => {
  jsonExpandedNodes.value.clear()
  rawDataExpanded.value = false
})
const copiedRawData = ref(false)
const copiedMdmData = ref(false)
const copiedTextBody = ref(false)
const copiedHtmlBody = ref(false)
const copiedEmlContent = ref(false)
const brokenScreenshots = ref<Record<string, boolean>>({})
const loadingScreenshots = ref<Record<string, boolean>>({})
const screenshotRetryCount = ref<Record<string, number>>({})

// Get the best screenshot source for a scan using shared utilities
function getPreferredScreenshotSrc(scan: UrlscanSubmission | null | undefined, index?: number): string | null {
  if (!scan) return null

  const urlshot = scan.screenshot_url || null
  // Use urlscanVerdict for consistent pending detection (matches display logic)
  const computedVerdict = urlscanVerdict(scan).toLowerCase()
  const isPending = isVerdictPending(computedVerdict)

  // Get retry count for cache busting
  const key = index !== undefined ? urlscanKey(scan, index) : ''
  const retryNum = key ? (screenshotRetryCount.value[key] || 0) : 0
  const cacheBuster = retryNum > 0 ? String(retryNum) : undefined

  // Prefer urlscan screenshot only when it's not a known placeholder and the scan is done
  if (urlshot && !isPlaceholderScreenshot(urlshot) && !isPending) {
    // Add cache buster for retries
    if (cacheBuster) {
      const separator = urlshot.includes('?') ? '&' : '?'
      return `${urlshot}${separator}_cb=${cacheBuster}`
    }
    return urlshot
  }

  // Fallback to liveshot URL
  return getLiveshotUrl(scan.url, { cacheBuster })
}

function hasValidScreenshot(scan: UrlscanSubmission, index: number): boolean {
  const key = urlscanKey(scan, index)
  // Don't try to load screenshots for pending scans - wait for backend polling to complete
  const verdict = urlscanVerdict(scan).toLowerCase()
  if (['pending', 'processing'].includes(verdict)) {
    return false  // Show "Scanning..." instead of trying to load image
  }
  const src = getPreferredScreenshotSrc(scan, index)
  return Boolean(src && !brokenScreenshots.value[key])
}

function isScreenshotLoading(scan: UrlscanSubmission, index: number): boolean {
  const key = urlscanKey(scan, index)
  return loadingScreenshots.value[key] === true
}

// Screenshot timeout tracking
const screenshotTimeouts = ref<Record<string, ReturnType<typeof setTimeout>>>({})
const MAX_AUTO_RETRIES = 3  // More retries for slow urlscan.io liveshots
const SCREENSHOT_TIMEOUT_MS = 15000 // 15 seconds timeout (liveshots can be slow)

function markScreenshotLoading(scan: UrlscanSubmission, index: number) {
  const key = urlscanKey(scan, index)
  loadingScreenshots.value[key] = true

  // Clear any existing timeout
  if (screenshotTimeouts.value[key]) {
    clearTimeout(screenshotTimeouts.value[key])
  }

  // Set a timeout - if screenshot doesn't load in time, auto-retry or mark as broken
  screenshotTimeouts.value[key] = setTimeout(() => {
    if (loadingScreenshots.value[key]) {
      const retryCount = screenshotRetryCount.value[key] || 0
      if (retryCount < MAX_AUTO_RETRIES) {
        // Auto-retry
        screenshotRetryCount.value[key] = retryCount + 1
        // Force re-render by toggling loading state
        loadingScreenshots.value[key] = false
        setTimeout(() => {
          loadingScreenshots.value[key] = true
        }, 100)
      } else {
        // Max retries reached, mark as broken

        loadingScreenshots.value[key] = false
        brokenScreenshots.value[key] = true
      }
    }
  }, SCREENSHOT_TIMEOUT_MS)
}

function markScreenshotLoaded(scan: UrlscanSubmission, index: number) {
  const key = urlscanKey(scan, index)
  // Clear timeout since it loaded successfully
  if (screenshotTimeouts.value[key]) {
    clearTimeout(screenshotTimeouts.value[key])
    delete screenshotTimeouts.value[key]
  }
  loadingScreenshots.value[key] = false
  brokenScreenshots.value[key] = false
}

function markScreenshotError(scan: UrlscanSubmission, index: number) {
  const key = urlscanKey(scan, index)
  // Clear timeout
  if (screenshotTimeouts.value[key]) {
    clearTimeout(screenshotTimeouts.value[key])
    delete screenshotTimeouts.value[key]
  }

  const retryCount = screenshotRetryCount.value[key] || 0
  if (retryCount < MAX_AUTO_RETRIES) {
    // Auto-retry on error
    screenshotRetryCount.value[key] = retryCount + 1
    loadingScreenshots.value[key] = false
    // Small delay before retry
    setTimeout(() => {
      loadingScreenshots.value[key] = true
    }, 500)
  } else {
    // Max retries reached
    loadingScreenshots.value[key] = false
    brokenScreenshots.value[key] = true
  }
}

function retryScreenshot(scan: UrlscanSubmission, index: number) {
  const key = urlscanKey(scan, index)
  // Manual retry RESETS counter to 0, so it gets 3 more auto-retry attempts
  screenshotRetryCount.value[key] = 0
  // Clear broken state to trigger re-render
  brokenScreenshots.value[key] = false
  loadingScreenshots.value[key] = true
  // Start timeout for this retry (will auto-retry if fails)
  markScreenshotLoading(scan, index)
}

// Track previous verdict state to detect transitions from pending to complete
const previousVerdicts = ref<Record<string, string>>({})

// Initialize screenshot loading state when urlscan submissions change
watch(
  () => urlscanSubmissions.value,
  (scans) => {
    if (!scans?.length) return
    scans.forEach((scan, index) => {
      const key = urlscanKey(scan, index)
      const currentVerdict = urlscanVerdict(scan).toLowerCase()
      const previousVerdict = previousVerdicts.value[key]

      // Track current verdict for next comparison
      previousVerdicts.value[key] = currentVerdict

      const isPending = ['pending', 'processing'].includes(currentVerdict)
      const wasPending = previousVerdict && ['pending', 'processing'].includes(previousVerdict)

      // Initialize loading state for new scans that are not pending
      if (loadingScreenshots.value[key] === undefined && !brokenScreenshots.value[key]) {
        if (!isPending) {
          // Start loading timeout for non-pending scans
          loadingScreenshots.value[key] = true
          markScreenshotLoading(scan, index)
        }
      }
      // Also trigger loading when a scan transitions from pending to complete
      else if (wasPending && !isPending && !brokenScreenshots.value[key]) {

        // Reset retry counter for fresh load
        screenshotRetryCount.value[key] = 0
        loadingScreenshots.value[key] = true
        markScreenshotLoading(scan, index)
      }
    })
  },
  { immediate: true }
)

// Cleanup timeouts on unmount
onUnmounted(() => {
  Object.values(screenshotTimeouts.value).forEach(timeout => {
    if (timeout) clearTimeout(timeout)
  })
})

// Insight/Rule Detail Dialog State
const insightDetailOpen = ref(false)
const selectedInsight = ref<{ title: string; severity: string; desc?: string; extraCount?: number; raw?: unknown } | null>(null)
const copiedInsightItem = ref<string | null>(null)
const copiedInsightAll = ref(false)
const ruleDetailOpen = ref(false)
const selectedRule = ref<{ title: string; severity: string; raw?: unknown } | null>(null)
const copiedRuleDetail = ref(false)
const ruleTreeExpanded = ref<Set<string>>(new Set(['rule'])) // Default expanded: rule object open, source collapsed

// Open insight detail dialog
function openInsightDetail(item: { title: string; severity: string; desc?: string; extraCount?: number; raw?: unknown }) {
  selectedInsight.value = item
  insightDetailOpen.value = true
  copiedInsightItem.value = null
  copiedInsightAll.value = false
}

// Open rule detail dialog
function openRuleDetail(item: { title: string; severity: string; raw?: unknown }) {
  selectedRule.value = item
  ruleDetailOpen.value = true
  copiedRuleDetail.value = false
  ruleTreeExpanded.value = new Set(['rule']) // Default: rule expanded, source collapsed
}

// Toggle rule tree node
function toggleRuleTreeNode(path: string) {
  if (ruleTreeExpanded.value.has(path)) {
    ruleTreeExpanded.value.delete(path)
  } else {
    ruleTreeExpanded.value.add(path)
  }
}

// Check if rule tree node is expanded
function isRuleTreeExpanded(path: string): boolean {
  return ruleTreeExpanded.value.has(path)
}

// Get insight detail items for display - extract actual values from raw data
function getInsightDetailItems(item: { title: string; desc?: string; raw?: unknown }): string[] {
  const items: string[] = []
  const seen = new Set<string>() // Avoid duplicates

  // Helper to add unique items
  function addItem(val: string): void {
    const trimmed = val.trim()
    // Filter out unhelpful values
    if (trimmed &&
      !seen.has(trimmed) &&
      !trimmed.match(/^List of \d+ items?$/i) &&
      !trimmed.match(/^Fields:/i) &&
      trimmed !== 'true' &&
      trimmed !== 'false' &&
      trimmed !== 'Yes' &&
      trimmed !== 'No' &&
      trimmed !== 'Condition matched' &&
      trimmed !== 'No match' &&
      trimmed !== 'null' &&
      trimmed !== '[]' &&
      trimmed !== '{}') {
      seen.add(trimmed)
      items.push(trimmed)
    }
  }

  // Helper to format an object as a readable string
  function formatObject(obj: Record<string, unknown>): string {
    const parts: string[] = []
    for (const [key, val] of Object.entries(obj)) {
      if (val !== null && val !== undefined && typeof val !== 'object') {
        parts.push(`${key}: ${val} `)
      }
    }
    return parts.length > 0 ? parts.join(', ') : ''
  }

  // Helper to extract display value from an object
  function extractObjectValue(obj: Record<string, unknown>): string | null {
    // Priority fields that typically contain the actual value
    const priorityFields = [
      'url', 'link', 'href', 'uri',  // URLs
      'domain', 'host', 'hostname',   // Domains
      'email', 'address', 'sender', 'recipient', 'from', 'to',  // Emails
      'ip', 'ip_address',  // IPs
      'name', 'value', 'text', 'content', 'data',  // Generic
      'path', 'file', 'filename',  // Files
      'subject', 'title', 'message',  // Text content
      'rule', 'rule_name', 'match', 'signature', 'identifier', 'id', 'type', 'description'  // Rules/YARA
    ]

    for (const field of priorityFields) {
      const val = obj[field]
      if (typeof val === 'string' && val.trim()) {
        return val.trim()
      }
    }
    return null
  }

  // Helper to recursively extract string values from nested arrays/structures
  // This is specifically designed to handle the Sublime insight data format:
  // - Simple strings: "value"
  // - Array of strings: ["a", "b", "c"]
  // - Nested arrays: [["a", "b"], ["c"]] or [[[...], [...]], [[...]]]
  // - Arrays with nulls: [[null], [null, null]] - should skip nulls
  // - Empty arrays: [[]] or [[], []] - should result in no items
  function extractValues(val: unknown, depth: number = 0): void {
    // Stop if too deep or null/undefined
    if (depth > 15 || val === null || val === undefined) return

    if (typeof val === 'string') {
      const trimmed = val.trim()
      if (trimmed) {
        addItem(trimmed)
      }
    } else if (typeof val === 'number') {
      // Add all numbers (including negatives like UTC offset -7)
      addItem(String(val))
    } else if (Array.isArray(val)) {
      // Process each item in the array - recursively handles nested arrays
      for (const v of val) {
        extractValues(v, depth + 1)
      }
    } else if (typeof val === 'object' && val !== null) {
      // For objects, try to extract meaningful values
      const obj = val as Record<string, unknown>
      const objVal = extractObjectValue(obj)
      if (objVal) {
        addItem(objVal)
      } else {
        // Try to format the object as key-value pairs
        const formatted = formatObject(obj)
        if (formatted) {
          addItem(formatted)
        } else {
          // Recurse into object fields
          for (const [, v] of Object.entries(obj)) {
            extractValues(v, depth + 1)
          }
        }
      }
    }
    // Skip booleans - they indicate condition match, not actual data
  }

  // Try to get actual result items from raw data
  if (item.raw && typeof item.raw === 'object') {
    const rawObj = item.raw as Record<string, unknown>
    const result = rawObj['result']

    // Only process result if it's not just a boolean
    if (result !== null && result !== undefined && typeof result !== 'boolean') {
      extractValues(result)
    }

    // If result was boolean or empty, check other fields in the raw hit
    if (items.length === 0) {
      // Look for common data fields in the hit object
      const dataFields = ['data', 'items', 'values', 'matches', 'findings', 'details', 'results']
      for (const field of dataFields) {
        const fieldVal = rawObj[field]
        if (fieldVal !== null && fieldVal !== undefined && typeof fieldVal !== 'boolean') {
          extractValues(fieldVal)
          if (items.length > 0) break
        }
      }
    }
  }

  // Fallback: show a message that no specific details are available
  if (items.length === 0) {
    items.push('No specific details available for this insight.')
  }

  return items
}

// Copy individual insight item
async function copyInsightItem(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    copiedInsightItem.value = text
    setTimeout(() => { copiedInsightItem.value = null }, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}

// Copy all insight items
async function copyInsightAll() {
  if (!selectedInsight.value) return
  try {
    const items = getInsightDetailItems(selectedInsight.value)
    const text = items.join('\n')
    await navigator.clipboard.writeText(text)
    copiedInsightAll.value = true
    setTimeout(() => { copiedInsightAll.value = false }, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}

// Get rule detail items for display - extract key info from raw rule data
/* Unused helper functions - kept for future reference
interface RuleDetailItem {
  label: string
  value: string
  isCode?: boolean
}

function getRuleDetailItems(item: { title: string; raw?: unknown }): RuleDetailItem[] {
  const items: RuleDetailItem[] = []
  
  if (!item.raw || typeof item.raw !== 'object') {
    return [{ label: 'Rule', value: item.title }]
  }
  
  const rawObj = item.raw as Record<string, unknown>
  const rule = rawObj['rule'] as Record<string, unknown> | undefined
  
  // Extract rule ID
  const ruleId = rule?.['id'] as string | undefined
  if (ruleId) {
    items.push({ label: 'Rule ID', value: ruleId })
  }
  
  // Extract rule name
  const ruleName = rule?.['name'] as string | undefined
  if (ruleName) {
    items.push({ label: 'Name', value: ruleName })
  }
  
  // Extract severity
  const severity = rule?.['severity'] as string | undefined
  if (severity) {
    items.push({ label: 'Severity', value: severity.toUpperCase() })
  }
  
  // Extract source (the detection logic) - this is the important part
  const source = rule?.['source'] as string | undefined
  if (source) {
    items.push({ label: 'Detection Logic', value: source, isCode: true })
  }
  
  // Extract matched status
  const matched = rawObj['matched']
  if (typeof matched === 'boolean') {
    items.push({ label: 'Matched', value: matched ? 'Yes' : 'No' })
  }
  
  return items
}

// Copy individual rule item
const copiedRuleItem = ref<string | null>(null)
async function copyRuleItem(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    copiedRuleItem.value = text
    setTimeout(() => { copiedRuleItem.value = null }, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}
*/

// Format rule data for display - makes source code readable
function formatRuleData(raw: unknown): string {
  if (!raw || typeof raw !== 'object') return ''

  const rawObj = raw as Record<string, unknown>
  const rule = rawObj['rule'] as Record<string, unknown> | undefined

  const lines: string[] = []

  // Rule info section
  if (rule) {
    lines.push('{')
    lines.push('  "rule": {')

    if (rule['id']) {
      lines.push(`    "id": "${rule['id']}", `)
    }
    if (rule['name']) {
      lines.push(`    "name": "${rule['name']}", `)
    }

    // Format source with proper line breaks
    if (rule['source'] && typeof rule['source'] === 'string') {
      const source = rule['source'] as string
      lines.push('    "source":')
      // Split by actual newlines and format each line
      const sourceLines = source.split('\n')
      sourceLines.forEach((line, idx) => {
        const prefix = idx === 0 ? '      ' : '      '
        const trimmedLine = line.replace(/^\s+/, (match) => '  '.repeat(Math.floor(match.length / 2)))
        lines.push(prefix + trimmedLine)
      })
      lines.push('')
    }

    if (rule['severity']) {
      lines.push(`    "severity": "${rule['severity']}"`)
    }

    lines.push('  },')
  }

  // Other fields
  if (typeof rawObj['matched'] === 'boolean') {
    lines.push(`  "matched": ${rawObj['matched']}, `)
  }
  if (typeof rawObj['success'] === 'boolean') {
    lines.push(`  "success": ${rawObj['success']}, `)
  }
  if (rawObj['error'] !== undefined) {
    lines.push(`  "error": ${rawObj['error'] === null ? 'null' : JSON.stringify(rawObj['error'])}, `)
  }
  if (rawObj['execution_time'] !== undefined) {
    lines.push(`  "execution_time": ${rawObj['execution_time']} `)
  }

  lines.push('}')

  return lines.join('\n')
}

// Copy rule detail
async function copyRuleDetail() {
  if (!selectedRule.value?.raw) return
  try {
    const text = formatRuleData(selectedRule.value.raw)
    await navigator.clipboard.writeText(text)
    copiedRuleDetail.value = true
    setTimeout(() => { copiedRuleDetail.value = false }, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}

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

// Helper for MDM tree view to get object/array length
function getObjLength(value: unknown): number {
  if (Array.isArray(value)) return value.length
  if (value && typeof value === 'object') return Object.keys(value).length
  return 0
}

function getItemLabel(value: unknown): string {
  const len = getObjLength(value)
  const bracket = Array.isArray(value) ? '[]' : '{}'
  return `${bracket} ${len} ${len === 1 ? 'item' : 'items'} `
}

async function copyRawData() {
  try {
    await navigator.clipboard.writeText(JSON.stringify(analysisResult.value, null, 2))
    copiedRawData.value = true
    setTimeout(() => copiedRawData.value = false, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}

async function copyMdmData() {
  try {
    await navigator.clipboard.writeText(JSON.stringify(mdmData.value, null, 2))
    copiedMdmData.value = true
    setTimeout(() => copiedMdmData.value = false, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}

async function copyTextBody() {
  try {
    await navigator.clipboard.writeText(rawTextBody.value || '')
    copiedTextBody.value = true
    setTimeout(() => copiedTextBody.value = false, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}

async function copyHtmlBody() {
  try {
    await navigator.clipboard.writeText(rawHtmlBody.value || '')
    copiedHtmlBody.value = true
    setTimeout(() => copiedHtmlBody.value = false, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}

async function copyEmlContent() {
  try {
    await navigator.clipboard.writeText(rawEmlContent.value || '')
    copiedEmlContent.value = true
    setTimeout(() => copiedEmlContent.value = false, 2000)
  } catch (err) {
    console.error('Failed to copy:', err)
  }
}

// Helper to get VT URL for different indicator types
const getVtUrl = (indicator: string, type: string, id?: string) => {
  if (type === 'url' && id) {
    return `https://www.virustotal.com/gui/url/${id}`
  }
  if (type === 'domain') {
    return `https://www.virustotal.com/gui/domain/${indicator}`
  }
  // For URLs and other types, use the search endpoint which handles lookups correctly
  return `https://www.virustotal.com/gui/search/${encodeURIComponent(indicator)}`
}

// Reactive cache for VT URL base64 IDs (pre-computed from urlscan submissions)
const vtUrlBase64s = ref<Map<string, string>>(new Map())

// Helper to compute base64url ID of URL for VirusTotal (without padding)
const computeVtUrlBase64 = (url: string): string => {
  return btoa(url)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

// Pre-compute VT base64 IDs when urlscan submissions change
watch(urlscanSubmissions, (submissions) => {
  for (const scan of submissions) {
    if (scan.url && !vtUrlBase64s.value.has(scan.url)) {
      try {
        const base64Id = computeVtUrlBase64(scan.url)
        vtUrlBase64s.value.set(scan.url, base64Id)
      } catch { }
    }
  }
}, { immediate: true, deep: true })

// Helper to get VT URL for a URL - uses base64url ID with url endpoint
// Shows existing results if available, triggers analysis if not found
const getVtUrlForUrl = (url: string): string => {
  if (!url) return ''

  // Use cached base64 ID if available
  const base64Id = vtUrlBase64s.value.get(url)
  if (base64Id) {
    // /gui/url/{base64} shows report or triggers scan
    return `https://www.virustotal.com/gui/url/${base64Id}`
  }

  // Compute on-the-fly if not cached
  try {
    const id = computeVtUrlBase64(url)
    return `https://www.virustotal.com/gui/url/${id}`
  } catch {
    // Fallback to search if encoding fails
    return `https://www.virustotal.com/gui/search/${encodeURIComponent(url)}`
  }
}

const getVtId = (indicator: string) => {
  return virusTotalSummaries.value.find(s => s.indicator === indicator)?.id
}

// Helper to get URLscan.io result URL - same logic as LinkAnalysisView
const getUrlscanUrl = (scan: { result_url?: string | null; scan_id?: string | null; url?: string | null }) => {
  // Use result_url if available
  if (scan.result_url) {
    return scan.result_url
  }

  // Fallback to constructing URL from scan_id
  if (scan.scan_id) {
    return `https://urlscan.io/result/${scan.scan_id}/`
  }

  // Fallback to URLscan search with domain
  if (scan.url) {
    try {
      const urlObj = new URL(scan.url.startsWith('http') ? scan.url : `https://${scan.url}`)
      return `https://urlscan.io/search/#domain:${urlObj.hostname}`
    } catch {
      return `https://urlscan.io/`
    }
  }

  return undefined
}

// Helper to get Hybrid Analysis result for a file hash
const getHaResultForFile = (sha256: string) => {
  return hybridAnalysisResults.value.find(ha => ha.sha256 === sha256) || null
}

// Helper to get VT result for a URL - checks both URL and domain lookups
const getUrlVtResult = (url: string | null | undefined) => {
  if (!url) return null

  // First try to find exact URL match (from vt_urls lookups)
  const urlResult = virusTotalSummaries.value.find(
    s => s.indicator_type === 'url' && s.indicator === url
  )
  if (urlResult) return urlResult

  // Fall back to domain match (from vt_domains lookups)
  try {
    const domain = new URL(url).hostname.replace(/^www\./, '')
    return virusTotalSummaries.value.find(
      s => s.indicator_type === 'domain' && s.indicator.toLowerCase() === domain.toLowerCase()
    ) || null
  } catch {
    return null
  }
}

// Keep old name for backward compatibility
const getDomainVtResult = getUrlVtResult

// Get ALL flagged domains from VirusTotal (domains that are malicious or suspicious)
// Also mark if they're covered by URLscan for display purposes
const allFlaggedDomains = computed(() => {
  // Get all domains from urlscan URLs for reference
  const urlscanDomains = new Set(
    urlscanSubmissions.value
      .filter(s => s.url)
      .map(s => {
        try {
          return new URL(s.url!).hostname.replace(/^www\./, '').toLowerCase()
        } catch {
          return null
        }
      })
      .filter(Boolean)
  )

  // Return ALL flagged domains with a flag indicating if they're in URLscan
  return vtFlaggedItems.value
    .filter(item => item.type === 'domain')
    .map(item => ({
      ...item,
      inUrlscan: urlscanDomains.has(item.indicator.toLowerCase())
    }))
})

// Attack score color for circle progress
const attackScoreColor = computed(() => {
  const score = attackScoreSummary.value?.score ?? 0
  if (score < 30) return '#10b981' // emerald-500
  if (score < 70) return '#eab308' // yellow-500
  return '#ef4444' // red-500
})

const SEVERITY_FILTERS = ['ALL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
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
          <ShieldCheck class="w-10 h-10 text-primary" />
        </div>

        <h1
          class="text-5xl md:text-6xl font-bold tracking-tight text-gray-900 dark:bg-gradient-to-b dark:from-white dark:to-white/60 dark:bg-clip-text dark:text-transparent drop-shadow-sm">
          EML Analyzer
        </h1>

        <p class="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
          Advanced automated email analysis powered by <span class="text-primary font-medium">Sublime Security</span>
          and threat intelligence.
        </p>
      </div>
    </section>

    <!-- Upload Section -->
    <section class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 mb-16 relative z-10">
      <div class="glass-panel rounded-3xl p-8 md:p-12 transition-all duration-500 hover:shadow-primary/5">

        <div class="flex flex-col items-center gap-8">
          <!-- Status Indicator -->
          <div
            class="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-sm font-medium transition-colors duration-300"
            :class="loading ? 'bg-primary/20 text-primary animate-pulse' : 'bg-secondary text-secondary-foreground'">
            <div class="w-2 h-2 rounded-full" :class="loading ? 'bg-primary' : 'bg-emerald-500'"></div>
            {{ loading ? 'Analyzing Artifact...' : 'System Ready' }}
          </div>

          <!-- Dropzone -->
          <div class="w-full max-w-2xl space-y-4">
            <input ref="fileInputRef" class="hidden" type="file" accept=".eml" @change="onFileChange" />

            <div class="relative group cursor-pointer" @click="triggerFileDialog" @dragenter.prevent="onDragOver"
              @dragover.prevent="onDragOver" @dragleave="onDragLeave" @drop="onDrop">
              <div
                class="relative flex flex-col items-center justify-center p-12 border-2 border-dashed rounded-2xl transition-all duration-300 bg-card/50 backdrop-blur-sm group-hover:bg-card/80"
                :class="[
                  isDragActive
                    ? 'border-primary bg-card/70 scale-[1.02] shadow-xl shadow-black/20'
                    : selectedFile
                      ? 'border-emerald-500 bg-emerald-50/50 dark:bg-emerald-950/20'
                      : 'border-border shadow-sm hover:shadow-md hover:border-primary/50'
                ]">
                <div v-if="!selectedFile">
                  <div
                    class="p-4 bg-background rounded-full shadow-sm mb-4 mx-auto w-fit group-hover:scale-110 transition-transform duration-300">
                    <UploadCloud class="w-8 h-8 text-primary" />
                  </div>
                  <h3 class="text-xl font-semibold mb-2 text-center">
                    Drop your .eml file here
                  </h3>
                  <p class="text-muted-foreground text-center">
                    or <span class="text-primary font-medium">click to browse</span>
                  </p>
                  <p class="text-xs text-muted-foreground mt-2 text-center">
                    Supports .eml files only
                  </p>
                </div>

                <div v-else class="flex items-center gap-4 w-full">
                  <div class="p-3 bg-emerald-100 dark:bg-emerald-900/40 rounded-xl shrink-0">
                    <FileText class="h-8 w-8 text-emerald-600" />
                  </div>
                  <div class="text-left min-w-0 flex-1">
                    <p class="font-semibold text-lg truncate">{{ selectedFileLabel }}</p>
                    <p class="text-sm text-muted-foreground">Ready to analyze</p>
                  </div>
                  <button @click.stop="clearFile"
                    class="p-2 hover:bg-destructive/10 text-muted-foreground hover:text-destructive rounded-full transition-colors shrink-0"
                    title="Remove file">
                    <Trash2 class="w-5 h-5" />
                  </button>
                </div>
              </div>
            </div>

            <button type="button"
              class="glass-button w-full px-8 py-4 rounded-xl font-medium flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed text-lg hover:scale-[1.01] active:scale-[0.99] transition-all"
              :disabled="isSubmitDisabled" @click="submit">
              <span v-if="loading" class="flex items-center gap-2">
                <RefreshCw class="w-5 h-5 animate-spin" /> Processing ({{ elapsedSeconds }}s)
              </span>
              <span v-else class="flex items-center gap-2">
                Analyze File
                <Search class="w-5 h-5" />
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
    <div v-if="analysisResult" class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 pb-20 animate-slide-up">

      <!-- Attack Score + Sublime Signal + AI Recommendation Combined Card -->
      <section class="glass-panel rounded-xl mb-10">
        <div class="p-6">
          <div class="flex flex-col lg:flex-row gap-6">
            <!-- Left: Attack Score Circle + Sublime Signal Counts -->
            <div class="flex flex-col items-center justify-center lg:pr-6 lg:border-r lg:border-border/30 shrink-0">
              <div class="relative w-28 h-28">
                <!-- Background circle -->
                <svg class="w-28 h-28 transform -rotate-90" viewBox="0 0 120 120">
                  <circle cx="60" cy="60" r="54" fill="none" stroke="currentColor" class="text-muted/20"
                    stroke-width="8" />
                  <!-- Progress circle -->
                  <circle cx="60" cy="60" r="54" fill="none" :stroke="attackScoreColor" stroke-width="8"
                    stroke-linecap="round" :stroke-dasharray="339.292"
                    :stroke-dashoffset="339.292 - (339.292 * (attackScoreSummary?.score ?? 0) / 100)"
                    class="transition-all duration-1000 ease-out" />
                </svg>
                <!-- Score text in center -->
                <div class="absolute inset-0 flex flex-col items-center justify-center">
                  <span class="text-2xl font-bold">{{ attackScoreSummary?.score ?? 0 }}</span>
                  <span class="text-xs text-muted-foreground">/ 100</span>
                </div>
              </div>
              <p class="text-sm font-medium mt-2" :style="{ color: attackScoreColor }">
                {{ attackScoreSummary?.verdict || 'Unknown' }}
              </p>
              <!-- Sublime Signal counts -->
              <div class="mt-4 pt-4 border-t border-border/30 flex items-center gap-3">
                <div class="flex items-center gap-2">
                  <ShieldAlert class="w-4 h-4 text-primary" />
                  <span class="text-xs text-muted-foreground">Rules:</span>
                  <span class="text-sm font-bold">{{ ruleSummary.matched }}</span>
                </div>
                <div class="w-px h-4 bg-border/50"></div>
                <div class="flex items-center gap-2">
                  <Lightbulb class="w-4 h-4 text-yellow-500" />
                  <span class="text-xs text-muted-foreground">Insights:</span>
                  <span class="text-sm font-bold">{{ ruleSummary.insights }}</span>
                </div>
              </div>
            </div>

            <!-- Right: Top Signals + AI Recommendation -->
            <div class="flex-1 min-w-0">
              <!-- Top Signals from Attack Score -->
              <div v-if="attackScoreSummary?.topSignals?.length" class="mb-5 pb-5 border-b border-border/30">
                <div class="flex items-center gap-3 mb-4">
                  <ShieldAlert class="w-5 h-5 text-primary" />
                  <p class="text-sm font-medium">Top Signals</p>
                </div>
                <div class="grid gap-2">
                  <div v-for="(signal, idx) in attackScoreSummary.topSignals.slice(0, 4)" :key="idx"
                    class="flex items-start gap-2 text-sm">
                    <span class="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                      :style="{ backgroundColor: attackScoreColor }"></span>
                    <span class="text-foreground/80">{{ signal.description }}</span>
                  </div>
                </div>
              </div>

              <!-- AI Recommendation -->
              <div class="flex items-center gap-3 mb-4">
                <Bot class="w-5 h-5 text-primary" />
                <p class="text-sm font-medium">AI Recommendation</p>
              </div>
              <div v-if="aiRecommendationLoading" class="flex items-center gap-3 text-muted-foreground">
                <Loader2 class="w-5 h-5 animate-spin" />
                <span>Analyzing...</span>
              </div>
              <div v-else-if="aiRecommendation" class="space-y-4">
                <!-- Risk Badge + Recommendation -->
                <div class="flex flex-col sm:flex-row sm:items-start gap-3">
                  <span class="px-3 py-1.5 rounded-md text-xs font-bold uppercase w-fit shrink-0" :class="{
                    'bg-emerald-500/20 text-emerald-400': aiRecommendation.risk_level === 'low',
                    'bg-yellow-500/20 text-yellow-400': aiRecommendation.risk_level === 'medium',
                    'bg-orange-500/20 text-orange-400': aiRecommendation.risk_level === 'high',
                    'bg-red-500/20 text-red-400': aiRecommendation.risk_level === 'critical'
                  }">{{ aiRecommendation.risk_level }}</span>
                  <p class="text-sm text-foreground/90 leading-relaxed flex-1">{{ aiRecommendation.recommendation }}</p>
                </div>
                <!-- Actions List -->
                <div v-if="aiRecommendation.actions.length" class="pt-3 border-t border-border/30">
                  <ul class="grid gap-2">
                    <li v-for="(action, idx) in aiRecommendation.actions" :key="idx"
                      class="flex items-center gap-3 text-sm text-muted-foreground">
                      <span class="w-1.5 h-1.5 rounded-full" :class="{
                        'bg-emerald-500': aiRecommendation.risk_level === 'low',
                        'bg-yellow-500': aiRecommendation.risk_level === 'medium',
                        'bg-orange-500': aiRecommendation.risk_level === 'high',
                        'bg-red-500': aiRecommendation.risk_level === 'critical'
                      }"></span>
                      {{ action }}
                    </li>
                  </ul>
                </div>
              </div>
              <p v-else class="text-muted-foreground text-sm">Recommendation unavailable</p>
            </div>
          </div>
        </div>
      </section>

      <!-- Insights & Detections Row (Insights are summary - more prominent) -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-10">
        <!-- Insights (Bigger - 2 columns as summary) -->
        <section v-if="analysisResult?.sublime.insight_hits?.length"
          class="glass-panel rounded-xl lg:col-span-2 flex flex-col overflow-hidden">
          <div class="p-5 border-b border-border/40 shrink-0">
            <h2 class="font-semibold mb-3 flex items-center gap-2">
              <Lightbulb class="w-5 h-5 text-yellow-500" />
              Insights Summary
              <span class="ml-auto px-2 py-0.5 rounded-md bg-primary/10 text-primary text-xs font-normal">
                {{ filteredUiInsightHits.length }}
              </span>
            </h2>
            <div class="flex flex-wrap gap-1.5">
              <button v-for="filter in SEVERITY_FILTERS" :key="filter" @click="insightSeverityFilter = filter"
                class="px-2 py-1 rounded text-xs transition-all" :class="insightSeverityFilter === filter
                  ? 'bg-primary/20 text-primary' : 'bg-secondary/50 text-muted-foreground hover:bg-secondary'">
                {{ filter.charAt(0) + filter.slice(1).toLowerCase() }}
                <span class="ml-0.5 opacity-60">({{ insightCounts[filter] ?? 0 }})</span>
              </button>
            </div>
          </div>
          <div class="divide-y divide-border/30 flex-1 overflow-y-auto max-h-80">
            <div v-for="(item, index) in displayedUiInsightHits" :key="index"
              class="p-4 cursor-pointer hover:bg-muted/30 transition-colors group" @click="openInsightDetail(item)">
              <div class="flex items-start justify-between gap-2">
                <p class="text-sm font-medium break-words flex-1">{{ item.title }}</p>
                <Eye
                  class="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                <span v-if="item.severity !== 'INFO'" class="w-2 h-2 rounded-full mt-1 shrink-0" :class="{
                  'bg-destructive': item.severity === 'HIGH',
                  'bg-yellow-500': item.severity === 'MEDIUM',
                  'bg-blue-500': item.severity === 'LOW'
                }"></span>
              </div>
              <p v-if="item.desc" class="text-xs text-muted-foreground mt-1 line-clamp-2">
                {{ item.desc }}
                <span v-if="item.extraCount" class="text-primary">+{{ item.extraCount }} more</span>
              </p>
            </div>
          </div>
        </section>

        <!-- Sublime Detections (Smaller - 1 column) -->
        <section v-if="analysisResult?.sublime.rule_hits?.length"
          class="glass-panel rounded-xl flex flex-col overflow-hidden">
          <div class="p-5 border-b border-border/40 flex items-center justify-between shrink-0">
            <h2 class="font-semibold flex items-center gap-2">
              <ShieldAlert class="w-5 h-5 text-primary" />
              Detection Rules
            </h2>
            <span class="px-2 py-1 rounded-md bg-primary/10 text-primary text-xs">
              {{ ruleSummary.matched }}
            </span>
          </div>
          <div class="divide-y divide-border/30 flex-1 overflow-y-auto max-h-80">
            <div v-for="(item, index) in displayedUiRuleHits" :key="index"
              class="p-4 cursor-pointer hover:bg-muted/30 transition-colors group" @click="openRuleDetail(item)">
              <div class="flex items-start gap-2">
                <h3 class="text-sm font-medium leading-tight flex-1 break-words">{{ item.title }}</h3>
                <Eye
                  class="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                <span v-if="item.severity" class="px-1.5 py-0.5 rounded text-xs font-medium uppercase shrink-0" :class="{
                  'bg-destructive/20 text-destructive': item.severity === 'HIGH' || item.severity === 'CRITICAL',
                  'bg-yellow-500/20 text-yellow-500': item.severity === 'MEDIUM',
                  'bg-blue-500/20 text-blue-500': item.severity === 'LOW',
                  'bg-muted text-muted-foreground': item.severity === 'INFO'
                }">{{ item.severity }}</span>
              </div>
            </div>
          </div>
        </section>
      </div>

      <!-- Key Metrics Row - All Security Tools -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
        <!-- Flagged Domains Card -->
        <div class="glass-panel p-5 rounded-xl">
          <p class="text-xs text-muted-foreground mb-3">Domain Analysis</p>
          <div v-if="vtByType.domainCount > 0" class="flex items-baseline gap-2">
            <span class="text-3xl font-bold" :class="allFlaggedDomains.length > 0 ? 'text-destructive' : ''">
              {{ allFlaggedDomains.length }}
            </span>
            <span class="text-xs text-muted-foreground">/ {{ vtByType.domainCount }} flagged</span>
          </div>
          <div v-else class="flex items-baseline gap-2">
            <span class="text-xl font-medium text-muted-foreground">No domains</span>
          </div>
          <div v-if="vtByType.domainCount > 0" class="flex flex-wrap gap-1.5 mt-3">
            <span class="px-2 py-0.5 rounded text-[10px] flex items-center gap-1"
              :class="vtByType.domainMalicious > 0 ? 'bg-red-500/20 text-red-400' : 'bg-secondary text-muted-foreground'">
              Malicious <span class="font-bold">{{ vtByType.domainMalicious }}</span>
            </span>
            <span class="px-2 py-0.5 rounded text-[10px] flex items-center gap-1"
              :class="vtByType.domainSuspicious > 0 ? 'bg-yellow-500/20 text-yellow-400' : 'bg-secondary text-muted-foreground'">
              Suspicious <span class="font-bold">{{ vtByType.domainSuspicious }}</span>
            </span>
            <span class="px-1.5 py-0.5 rounded text-[10px] bg-blue-500/10 text-blue-400">VirusTotal</span>
          </div>
        </div>

        <!-- Link Analysis Card -->
        <div class="glass-panel p-5 rounded-xl">
          <div class="flex items-center justify-between mb-3">
            <p class="text-xs text-muted-foreground">Link Analysis</p>
            <span v-if="threatIntelAlerts.length > 0"
              class="px-2 py-0.5 rounded-full text-[10px] bg-yellow-500/20 text-yellow-400 flex items-center gap-1"
              title="Tools disagree on threat detection">
              ?? {{ threatIntelAlerts.length }} alert{{ threatIntelAlerts.length > 1 ? 's' : '' }}
            </span>
          </div>
          <div class="flex items-baseline gap-2">
            <span class="text-3xl font-bold"
              :class="(linkAnalysisBreakdown.urlscan > 0 || linkAnalysisBreakdown.sublimeMl > 0 || linkAnalysisBreakdown.virustotal > 0) ? 'text-destructive' : ''">
              {{ Math.max(linkAnalysisBreakdown.urlscan, linkAnalysisBreakdown.sublimeMl,
                linkAnalysisBreakdown.virustotal) }}
            </span>
            <span class="text-xs text-muted-foreground">/ {{ linkAnalysisBreakdown.total }} flagged</span>
          </div>
          <div class="flex flex-wrap gap-1.5 mt-3">
            <span class="px-2 py-0.5 rounded text-[10px] flex items-center gap-1"
              :class="linkAnalysisBreakdown.urlscan > 0 ? 'bg-red-500/20 text-red-400' : 'bg-primary/10 text-primary'">
              URLscan <span class="font-bold">{{ linkAnalysisBreakdown.urlscan }}</span>
            </span>
            <span class="px-2 py-0.5 rounded text-[10px] flex items-center gap-1"
              :class="linkAnalysisBreakdown.sublimeMl > 0 ? 'bg-red-500/20 text-red-400' : 'bg-purple-500/10 text-purple-400'">
              Sublime ML <span class="font-bold">{{ linkAnalysisBreakdown.sublimeMl }}</span>
            </span>
            <span class="px-2 py-0.5 rounded text-[10px] flex items-center gap-1"
              :class="linkAnalysisBreakdown.virustotal > 0 ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/10 text-blue-400'">
              VirusTotal <span class="font-bold">{{ linkAnalysisBreakdown.virustotal }}</span>
            </span>
          </div>
        </div>

        <!-- IP Reputation Card -->
        <div class="glass-panel p-5 rounded-xl">
          <p class="text-xs text-muted-foreground mb-3">IP Reputation</p>
          <div v-if="ipqsSummary.total > 0" class="flex items-baseline gap-2">
            <span class="text-3xl font-bold" :class="ipqsSummary.flagged > 0 ? 'text-destructive' : ''">
              {{ ipqsSummary.flagged }}
            </span>
            <span class="text-xs text-muted-foreground">/ {{ ipqsSummary.total }} suspicious</span>
          </div>
          <div v-else class="flex items-baseline gap-2">
            <span class="text-xl font-medium text-muted-foreground">No IPs</span>
          </div>
          <div class="flex flex-wrap gap-1 mt-2">
            <span class="px-1.5 py-0.5 rounded text-[10px] bg-orange-500/10 text-orange-400">IPQS</span>
            <span v-if="ipqsSummary.vpn" class="px-1.5 py-0.5 rounded text-[10px] bg-yellow-500/10 text-yellow-400">{{
              ipqsSummary.vpn }} VPN</span>
            <span v-if="ipqsSummary.proxy" class="px-1.5 py-0.5 rounded text-[10px] bg-yellow-500/10 text-yellow-400">{{
              ipqsSummary.proxy }} Proxy</span>
            <span v-if="ipqsSummary.tor" class="px-1.5 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400">{{
              ipqsSummary.tor }} Tor</span>
          </div>
        </div>

        <!-- File Analysis Card -->
        <div class="glass-panel p-5 rounded-xl">
          <p class="text-xs text-muted-foreground mb-3">File Analysis</p>
          <div v-if="fileAnalysisBreakdown.total > 0" class="flex items-baseline gap-2">
            <span class="text-3xl font-bold"
              :class="(fileAnalysisBreakdown.virustotal > 0 || fileAnalysisBreakdown.hybridAnalysis > 0) ? 'text-destructive' : ''">
              {{ Math.max(fileAnalysisBreakdown.virustotal, fileAnalysisBreakdown.hybridAnalysis) }}
            </span>
            <span class="text-xs text-muted-foreground">/ {{ fileAnalysisBreakdown.total }} flagged</span>
          </div>
          <div v-else class="flex items-baseline gap-2">
            <span class="text-xl font-medium text-muted-foreground">No files</span>
          </div>
          <div class="flex flex-wrap gap-1.5 mt-3">
            <span v-if="fileAnalysisBreakdown.total > 0" class="px-2 py-0.5 rounded text-[10px] flex items-center gap-1"
              :class="fileAnalysisBreakdown.virustotal > 0 ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/10 text-blue-400'">
              VirusTotal <span class="font-bold">{{ fileAnalysisBreakdown.virustotal }}</span>
            </span>
            <span v-if="fileAnalysisBreakdown.total > 0" class="px-2 py-0.5 rounded text-[10px] flex items-center gap-1"
              :class="fileAnalysisBreakdown.hybridAnalysis > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/10 text-green-400'">
              Hybrid Analysis <span class="font-bold">{{ fileAnalysisBreakdown.hybridAnalysis }}</span>
            </span>
          </div>
        </div>
      </div>

      <!-- Threat Analysis (Combined: Flagged Domains + Links + Files) -->
      <section class="glass-panel rounded-xl mb-10">
        <div class="p-6 border-b border-border/40 flex items-center gap-3">
          <ShieldAlert class="w-6 h-6 text-primary" />
          <h2 class="font-semibold text-lg">Threat Analysis</h2>
        </div>

        <div class="p-6 space-y-6">
          <!-- 1. Flagged Domains Card -->
          <div v-if="allFlaggedDomains.length" class="bg-card/50 rounded-xl border border-border/50 overflow-hidden">
            <div class="px-5 py-4 border-b border-border/30 flex items-center gap-3 bg-blue-500/5">
              <div class="w-8 h-8 rounded-lg bg-blue-500/20 flex items-center justify-center">
                <Globe class="w-4 h-4 text-blue-500" />
              </div>
              <span class="font-semibold">Flagged Domains</span>
              <span class="ml-auto px-3 py-1 rounded-full bg-destructive/20 text-destructive text-xs font-semibold">
                {{ allFlaggedDomains.length }} flagged
              </span>
            </div>
            <div class="divide-y divide-border/30">
              <div v-for="item in allFlaggedDomains" :key="item.indicator"
                class="p-5 flex items-center gap-4 hover:bg-secondary/30 transition-colors">
                <div class="w-10 h-10 rounded-lg flex items-center justify-center shrink-0 bg-blue-500/10">
                  <Globe class="w-5 h-5 text-blue-500" />
                </div>
                <div class="min-w-0 flex-1">
                  <p class="font-mono text-sm truncate" :title="item.indicator">{{ item.indicator }}</p>
                  <p class="text-xs text-muted-foreground mt-1">
                    {{ item.maliciousCount }}/{{ item.total }} engines flagged
                  </p>
                </div>
                <span class="px-3 py-1 rounded-full text-xs font-semibold" :class="{
                  'bg-destructive/20 text-destructive': item.verdict === 'Malicious',
                  'bg-yellow-500/20 text-yellow-500': item.verdict === 'Suspicious'
                }">{{ item.verdict }}</span>
                <div class="flex items-center gap-1">
                  <button @click="copyHash(item.indicator)" class="p-2 hover:bg-secondary rounded-lg transition-colors"
                    :title="copiedHashes[item.indicator] ? 'Copied!' : 'Copy'">
                    <CheckCircle2 v-if="copiedHashes[item.indicator]" class="w-4 h-4 text-emerald-500" />
                    <Copy v-else class="w-4 h-4 text-muted-foreground" />
                  </button>
                  <a :href="getVtUrl(item.indicator, 'domain')" target="_blank"
                    class="p-2 hover:bg-secondary rounded-lg transition-colors" title="View on VirusTotal">
                    <ExternalLink class="w-4 h-4 text-muted-foreground" />
                  </a>
                </div>
              </div>
            </div>
          </div>

          <!-- 2. Link Analysis Card -->
          <div v-if="urlscanSubmissions.length" class="bg-card/50 rounded-xl border border-border/50 overflow-hidden">
            <div class="px-5 py-4 border-b border-border/30 flex items-center gap-3 bg-purple-500/5">
              <div class="w-8 h-8 rounded-lg bg-purple-500/20 flex items-center justify-center">
                <Search class="w-4 h-4 text-purple-500" />
              </div>
              <span class="font-semibold">Link Analysis</span>
              <span class="ml-auto text-sm text-muted-foreground">
                {{ urlscanSubmissions.length }} URL(s)
              </span>
            </div>
            <div class="divide-y divide-border/30">
              <div v-for="(scan, index) in urlscanSubmissions" :key="urlscanKey(scan, index)"
                class="p-5 hover:bg-secondary/30 transition-colors">
                <div class="flex gap-5">
                  <!-- Screenshot Preview - Fixed Size -->
                  <div
                    class="w-[160px] h-[100px] rounded-lg overflow-hidden bg-muted/50 relative group shrink-0 border border-border/50">
                    <template v-if="hasValidScreenshot(scan, index)">
                      <div class="w-full h-full relative bg-black/20">
                        <a :href="scan.result_url" target="_blank" class="block w-full h-full" v-if="scan.result_url">
                          <img :src="getPreferredScreenshotSrc(scan, index) || undefined" :alt="`Scan ${index + 1}`"
                            class="w-full h-full object-cover object-top" loading="lazy"
                            @load="markScreenshotLoaded(scan, index)" @error="markScreenshotError(scan, index)" />
                          <div
                            class="absolute inset-0 flex items-center justify-center bg-black/60 opacity-0 group-hover:opacity-100 transition-opacity">
                            <ExternalLink class="w-5 h-5 text-white" />
                          </div>
                        </a>
                        <img v-else :src="getPreferredScreenshotSrc(scan, index) || undefined"
                          :alt="`Scan ${index + 1}`" class="w-full h-full object-cover object-top" loading="lazy"
                          @load="markScreenshotLoaded(scan, index)" @error="markScreenshotError(scan, index)" />
                      </div>
                    </template>
                    <!-- If pending, no screenshot URL, or failed to load -->
                    <div v-else
                      class="w-full h-full flex flex-col items-center justify-center text-muted-foreground gap-1">
                      <template v-if="['pending', 'processing'].includes(urlscanVerdict(scan).toLowerCase())">
                        <RefreshCw class="w-5 h-5 text-muted-foreground/50 animate-spin" />
                        <span class="text-xs">Scanning...</span>
                      </template>
                      <template v-else>
                        <Monitor class="w-6 h-6 text-muted-foreground/40 mb-1" />
                        <Button variant="outline" size="sm" @click="retryScreenshot(scan, index)" class="gap-1.5">
                          <RefreshCw class="w-3.5 h-3.5" />
                          Retry
                        </Button>
                      </template>
                    </div>
                  </div>

                  <!-- URL Details -->
                  <div class="flex-1 min-w-0 flex flex-col">
                    <!-- URL with copy -->
                    <div class="flex items-start gap-2 mb-3">
                      <p class="text-sm font-mono truncate flex-1 pt-0.5" :title="scan.url || ''">{{ scan.url }}</p>
                      <button @click.prevent="copyTarget(index, scan.url || '')"
                        class="p-1.5 hover:bg-secondary rounded-lg transition-colors shrink-0" title="Copy URL">
                        <Copy v-if="!copiedTargets[index]" class="w-4 h-4 text-muted-foreground" />
                        <CheckCircle2 v-else class="w-4 h-4 text-emerald-500" />
                      </button>
                    </div>

                    <!-- Effective URL (if redirected) -->
                    <div v-if="scan.ml_link?.effective_url && scan.ml_link.effective_url !== scan.url"
                      class="mb-3 text-xs bg-orange-500/10 border border-orange-500/30 rounded-lg p-2 overflow-hidden">
                      <span class="text-orange-600 font-medium">Redirects to:</span>
                      <span class="text-orange-500 ml-1 font-mono truncate block" :title="scan.ml_link.effective_url">{{
                        scan.ml_link.effective_url }}</span>
                    </div>

                    <!-- Verdicts in a nice grid -->
                    <div class="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm mb-3">
                      <div class="flex items-center gap-2">
                        <span class="text-muted-foreground text-xs">Urlscan</span>
                        <span class="px-2.5 py-0.5 rounded-full text-xs font-medium" :class="{
                          'bg-destructive/20 text-destructive': (scan.verdict || urlscanVerdict(scan))?.toLowerCase() === 'malicious',
                          'bg-emerald-500/20 text-emerald-500': (scan.verdict || urlscanVerdict(scan))?.toLowerCase() === 'benign' || (scan.verdict || urlscanVerdict(scan))?.toLowerCase() === 'clean',
                          'bg-secondary text-muted-foreground': !['malicious', 'benign', 'clean'].includes((scan.verdict || urlscanVerdict(scan))?.toLowerCase() || '')
                        }">{{ scan.verdict || urlscanVerdict(scan) || 'Pending' }}</span>
                      </div>
                      <div v-if="scan.ml_link" class="flex items-center gap-2">
                        <span class="text-muted-foreground text-xs">Sublime ML</span>
                        <span class="px-2.5 py-0.5 rounded-full text-xs font-medium capitalize" :class="{
                          'bg-destructive/20 text-destructive': ['malicious', 'phishing', 'credential_phishing'].includes(scan.ml_link.label?.toLowerCase() || ''),
                          'bg-yellow-500/20 text-yellow-500': scan.ml_link.label?.toLowerCase() === 'suspicious',
                          'bg-emerald-500/20 text-emerald-500': ['benign', 'safe', 'clean'].includes(scan.ml_link.label?.toLowerCase() || ''),
                          'bg-secondary text-muted-foreground': !['malicious', 'phishing', 'credential_phishing', 'suspicious', 'benign', 'safe', 'clean'].includes(scan.ml_link.label?.toLowerCase() || '')
                        }">{{ scan.ml_link.label || 'N/A' }}</span>
                        <span v-if="scan.ml_link.score !== null && scan.ml_link.score !== undefined"
                          class="text-xs text-muted-foreground">({{ (Number(scan.ml_link.score) * 100).toFixed(0)
                          }}%)</span>
                      </div>
                      <div v-if="scan.url" class="flex items-center gap-2">
                        <span class="text-muted-foreground text-xs">VirusTotal</span>
                        <template v-if="getDomainVtResult(scan.url)">
                          <span class="px-2.5 py-0.5 rounded-full text-xs font-medium" :class="{
                            'bg-destructive/20 text-destructive': getDomainVtResult(scan.url)?.verdict === 'Malicious',
                            'bg-yellow-500/20 text-yellow-500': getDomainVtResult(scan.url)?.verdict === 'Suspicious',
                            'bg-emerald-500/20 text-emerald-500': ['Clean', 'No detections'].includes(getDomainVtResult(scan.url)?.verdict || '')
                          }">{{ getDomainVtResult(scan.url)?.verdict }}</span>
                          <span class="text-xs text-muted-foreground">({{ getDomainVtResult(scan.url)?.stats?.malicious
                            || 0 }}/{{ getDomainVtResult(scan.url)?.total }})</span>
                        </template>
                        <span v-else
                          class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-secondary text-muted-foreground">No
                          data</span>
                      </div>
                    </div>

                    <!-- Computer Vision Indicators -->
                    <div
                      v-if="scan.ml_link && (scan.ml_link.contains_login || scan.ml_link.contains_captcha || (scan.ml_link.redirect_count ?? 0) > 0)"
                      class="flex flex-wrap gap-2 mb-3">
                      <span v-if="scan.ml_link.contains_login"
                        class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-yellow-500/20 text-yellow-600">
                        <KeyRound class="w-3 h-3" /> Login Form
                      </span>
                      <span v-if="scan.ml_link.contains_captcha"
                        class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-blue-500/20 text-blue-600">
                        <ShieldCheck class="w-3 h-3" /> CAPTCHA
                      </span>
                      <span v-if="(scan.ml_link.redirect_count ?? 0) > 0"
                        class="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-orange-500/20 text-orange-600">
                        <ArrowRight class="w-3 h-3" /> {{ scan.ml_link.redirect_count }} Redirect{{
                          (scan.ml_link.redirect_count ?? 0) > 1
                            ? 's' : '' }}
                      </span>
                    </div>

                    <!-- Actions -->
                    <div class="flex items-center gap-3 mt-auto">
                      <a v-if="getUrlscanUrl(scan)" :href="getUrlscanUrl(scan)" target="_blank"
                        class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-secondary/50 hover:bg-secondary text-xs font-medium transition-colors">
                        <ExternalLink class="w-3.5 h-3.5" /> Urlscan Report
                      </a>
                      <a v-if="scan.url" :href="getVtUrlForUrl(scan.url)" target="_blank"
                        class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-secondary/50 hover:bg-secondary text-xs font-medium transition-colors">
                        <ExternalLink class="w-3.5 h-3.5" /> VT Report
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Scan More URLs Button -->
            <div v-if="hasMoreUrlsToScan" class="px-5 py-4 border-t border-border/30 bg-amber-500/5">
              <div class="flex items-center justify-between gap-4">
                <div class="flex items-center gap-2 text-sm">
                  <AlertTriangle class="w-4 h-4 text-amber-500" />
                  <span class="text-muted-foreground">
                    <span class="font-medium text-amber-600">{{ skippedUrlCount }}</span> additional URL(s) were not
                    scanned to save
                    quota
                  </span>
                </div>
                <div class="flex items-center gap-2">
                  <button @click="scanMoreUrls(20)" :disabled="scanningMoreUrls"
                    class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 text-purple-600 text-xs font-medium transition-colors disabled:opacity-50">
                    <Plus class="w-3.5 h-3.5" />
                    {{ scanningMoreUrls ? 'Scanning...' : 'Scan 20 More' }}
                  </button>
                  <button @click="scanAllUrls()" :disabled="scanningMoreUrls"
                    class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-700 text-white text-xs font-medium transition-colors disabled:opacity-50">
                    <Search class="w-3.5 h-3.5" />
                    {{ scanningMoreUrls ? 'Scanning...' : 'Scan All' }}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- 3. File Attachments Card (with Hybrid Analysis) -->
          <div v-if="attachmentSummary && attachmentSummary.total > 0" id="attachments-section"
            class="bg-card/50 rounded-xl border border-border/50 overflow-hidden">
            <div class="px-5 py-4 border-b border-border/30 flex items-center gap-3 bg-orange-500/5">
              <div class="w-8 h-8 rounded-lg bg-orange-500/20 flex items-center justify-center">
                <FileText class="w-4 h-4 text-orange-500" />
              </div>
              <span class="font-semibold">File Attachments</span>
              <span class="ml-auto text-sm text-muted-foreground">
                {{ attachmentSummary.total }} file(s)
              </span>
            </div>
            <div class="divide-y divide-border/30">
              <div v-for="file in attachmentSummary.samples" :key="file.filename"
                class="p-5 hover:bg-secondary/30 transition-colors">
                <div class="flex items-center gap-4">
                  <div class="w-12 h-12 rounded-lg flex items-center justify-center shrink-0"
                    :class="file.isDangerous ? 'bg-destructive/10' : 'bg-orange-500/10'">
                    <FileText class="w-6 h-6" :class="file.isDangerous ? 'text-destructive' : 'text-orange-500'" />
                  </div>
                  <div class="min-w-0 flex-1">
                    <p class="font-medium flex items-center gap-2">
                      {{ file.filename }}
                      <span v-if="file.isDangerous"
                        class="px-2 py-0.5 rounded text-[10px] font-bold bg-destructive/20 text-destructive uppercase">
                        Risky
                      </span>
                    </p>
                    <p class="text-sm text-muted-foreground mt-1">
                      {{ file.fileCategory }} � {{ file.sizeLabel }}
                    </p>
                  </div>
                </div>

                <!-- VirusTotal Results for this file -->
                <div v-if="file.sha256" class="mt-4 p-3 bg-blue-500/5 rounded-lg border border-blue-500/20">
                  <div class="flex items-center gap-2 mb-2">
                    <ShieldCheck class="w-4 h-4 text-blue-500" />
                    <span class="text-xs font-medium text-blue-500">VirusTotal</span>
                  </div>
                  <div class="flex items-center justify-between gap-4">
                    <div class="flex-1 text-xs text-muted-foreground">
                      <template v-if="getVtResultForFile(file.sha256)">
                        {{ getVtResultForFile(file.sha256)?.stats?.malicious || 0 }}/{{
                          getVtResultForFile(file.sha256)?.total || 0 }} engines detected this file
                      </template>
                      <span v-else>Scanning...</span>
                    </div>
                    <div class="flex items-center gap-2">
                      <template v-if="getVtResultForFile(file.sha256)">
                        <span class="px-2.5 py-0.5 rounded-full text-xs font-semibold" :class="{
                          'bg-destructive/20 text-destructive': getVtResultForFile(file.sha256)?.verdict === 'Malicious',
                          'bg-yellow-500/20 text-yellow-500': getVtResultForFile(file.sha256)?.verdict === 'Suspicious',
                          'bg-emerald-500/20 text-emerald-500': getVtResultForFile(file.sha256)?.verdict === 'Clean'
                        }">
                          {{ getVtResultForFile(file.sha256)?.verdict }}
                        </span>
                      </template>
                      <span v-else
                        class="px-2.5 py-0.5 rounded-full text-xs font-medium bg-secondary text-muted-foreground">
                        Pending
                      </span>
                      <button @click="openVtForFile(file.sha256)"
                        class="p-1.5 hover:bg-secondary rounded transition-colors" title="View on VirusTotal">
                        <ExternalLink class="w-3.5 h-3.5 text-blue-500" />
                      </button>
                    </div>
                  </div>
                </div>

                <!-- Hybrid Analysis Results for this file -->
                <div v-if="file.sha256 && getHaResultForFile(file.sha256)"
                  class="mt-3 p-3 bg-violet-500/5 rounded-lg border border-violet-500/20">
                  <div class="flex items-center gap-2 mb-2">
                    <Database class="w-4 h-4 text-violet-500" />
                    <span class="text-xs font-medium text-violet-500">Hybrid Analysis Sandbox</span>
                  </div>
                  <div class="flex items-center justify-between gap-4">
                    <div class="flex-1 text-xs text-muted-foreground">
                      <span v-if="getHaResultForFile(file.sha256)?.file_type">{{
                        getHaResultForFile(file.sha256)?.file_type
                      }}</span>
                      <span v-if="getHaResultForFile(file.sha256)?.vx_family" class="text-destructive font-medium"> � {{
                        getHaResultForFile(file.sha256)?.vx_family }}</span>
                      <span v-if="getHaResultForFile(file.sha256)?.environment_description"> � {{
                        getHaResultForFile(file.sha256)?.environment_description }}</span>
                    </div>
                    <div class="flex items-center gap-2">
                      <span
                        v-if="getHaResultForFile(file.sha256)?.av_detect && getHaResultForFile(file.sha256)!.av_detect! > 0"
                        class="px-2 py-0.5 rounded text-[10px] font-bold bg-destructive/20 text-destructive uppercase">
                        {{ getHaResultForFile(file.sha256)?.av_detect }} AV
                      </span>
                      <span v-if="getHaResultForFile(file.sha256)?.verdict"
                        class="px-2.5 py-0.5 rounded-full text-xs font-semibold capitalize" :class="{
                          'bg-destructive/20 text-destructive': getHaResultForFile(file.sha256)?.verdict === 'malicious',
                          'bg-yellow-500/20 text-yellow-600': getHaResultForFile(file.sha256)?.verdict === 'suspicious',
                          'bg-emerald-500/20 text-emerald-600': getHaResultForFile(file.sha256)?.verdict === 'no specific threat' || getHaResultForFile(file.sha256)?.verdict === 'not found',
                          'bg-secondary text-muted-foreground': !['malicious', 'suspicious', 'no specific threat', 'not found'].includes(getHaResultForFile(file.sha256)?.verdict || '')
                        }">
                        {{ getHaResultForFile(file.sha256)?.verdict }}
                      </span>
                      <span
                        v-if="getHaResultForFile(file.sha256)?.threat_score !== null && getHaResultForFile(file.sha256)?.threat_score !== undefined"
                        class="text-xs text-muted-foreground">
                        Score: {{ getHaResultForFile(file.sha256)?.threat_score }}/100
                      </span>
                      <a v-if="getHaResultForFile(file.sha256)?.report_url"
                        :href="getHaResultForFile(file.sha256)?.report_url!" target="_blank"
                        class="p-1.5 hover:bg-secondary rounded transition-colors" title="View on Hybrid Analysis">
                        <ExternalLink class="w-3.5 h-3.5 text-violet-500" />
                      </a>
                    </div>
                  </div>
                  <p v-if="getHaResultForFile(file.sha256)?.error" class="text-xs text-destructive mt-2">{{
                    getHaResultForFile(file.sha256)?.error }}</p>
                </div>

                <details v-if="file.sha256" class="mt-4">
                  <summary
                    class="text-xs text-muted-foreground cursor-pointer hover:text-foreground inline-flex items-center gap-1">
                    <ChevronDown class="w-3 h-3" /> Show file hash
                  </summary>
                  <div class="mt-2 p-3 bg-muted/50 rounded-lg flex items-center justify-between gap-3">
                    <code class="text-xs font-mono break-all select-all flex-1 text-muted-foreground">
            {{ file.sha256 }}
          </code>
                    <button @click="copyHash(file.sha256)"
                      class="p-2 hover:bg-secondary rounded-lg transition-colors shrink-0"
                      :title="copiedHashes[file.sha256] ? 'Copied!' : 'Copy'">
                      <CheckCircle2 v-if="copiedHashes[file.sha256]" class="w-4 h-4 text-emerald-500" />
                      <Copy v-else class="w-4 h-4 text-muted-foreground" />
                    </button>
                  </div>
                </details>
              </div>
            </div>
          </div>

          <!-- 4. IP Reputation Card (IPQS) -->
          <div v-if="ipqsResults.length" class="bg-card/50 rounded-xl border border-border/50 overflow-hidden">
            <div class="px-5 py-4 border-b border-border/30 flex items-center gap-3 bg-cyan-500/5">
              <div class="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                <Server class="w-4 h-4 text-cyan-500" />
              </div>
              <span class="font-semibold">IP Reputation</span>
              <span class="ml-auto text-sm text-muted-foreground">
                {{ ipqsResults.length }} IP(s) analyzed
              </span>
            </div>
            <div class="divide-y divide-border/30">
              <div v-for="ip in ipqsResults" :key="ip.ip" class="p-5 hover:bg-secondary/30 transition-colors">
                <div class="flex items-center gap-4">
                  <div class="w-12 h-12 rounded-lg flex items-center justify-center shrink-0"
                    :class="ip.fraud_score && ip.fraud_score >= 75 ? 'bg-destructive/10' : ip.fraud_score && ip.fraud_score >= 50 ? 'bg-yellow-500/10' : 'bg-cyan-500/10'">
                    <Wifi class="w-6 h-6"
                      :class="ip.fraud_score && ip.fraud_score >= 75 ? 'text-destructive' : ip.fraud_score && ip.fraud_score >= 50 ? 'text-yellow-500' : 'text-cyan-500'" />
                  </div>
                  <div class="min-w-0 flex-1">
                    <div class="flex items-center gap-2">
                      <p class="font-mono text-sm">{{ ip.ip }}</p>
                      <span v-if="ip.source"
                        class="px-2 py-0.5 rounded text-[10px] font-medium bg-cyan-500/10 text-cyan-600">
                        {{ ip.source }}
                      </span>
                    </div>
                    <p class="text-xs text-muted-foreground mt-1">
                      {{ ip.isp || 'Unknown ISP' }} � {{ ip.city || 'Unknown' }}, {{ ip.country_code || '??' }}
                    </p>
                  </div>
                  <div class="flex items-center gap-3 shrink-0">
                    <!-- Risk indicators -->
                    <div class="flex items-center gap-1.5">
                      <span v-if="ip.is_vpn"
                        class="px-2 py-0.5 rounded text-[10px] font-bold bg-yellow-500/20 text-yellow-600 uppercase">VPN</span>
                      <span v-if="ip.is_tor"
                        class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-600 uppercase">TOR</span>
                      <span v-if="ip.is_proxy"
                        class="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-500/20 text-orange-600 uppercase">Proxy</span>
                      <span v-if="ip.is_bot"
                        class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/20 text-red-600 uppercase">Bot</span>
                      <span v-if="ip.recent_abuse"
                        class="px-2 py-0.5 rounded text-[10px] font-bold bg-destructive/20 text-destructive uppercase">Abuse</span>
                    </div>
                    <!-- Fraud Score -->
                    <div class="text-right">
                      <span v-if="ip.fraud_score !== null && ip.fraud_score !== undefined"
                        class="px-3 py-1 rounded-full text-xs font-semibold" :class="{
                          'bg-destructive/20 text-destructive': ip.fraud_score >= 75,
                          'bg-yellow-500/20 text-yellow-600': ip.fraud_score >= 50 && ip.fraud_score < 75,
                          'bg-emerald-500/20 text-emerald-600': ip.fraud_score < 50
                        }">
                        Score: {{ ip.fraud_score }}
                      </span>
                      <span v-else-if="ip.error"
                        class="px-3 py-1 rounded-full text-xs font-medium bg-secondary text-muted-foreground">
                        Error
                      </span>
                    </div>
                  </div>
                </div>
                <!-- Error message if any -->
                <p v-if="ip.error" class="text-xs text-destructive mt-2">{{ ip.error }}</p>
              </div>
            </div>
          </div>

          <!-- Empty State -->
          <div
            v-if="!allFlaggedDomains.length && !urlscanSubmissions.length && (!attachmentSummary || attachmentSummary.total === 0) && !ipqsResults.length"
            class="py-16 text-center text-muted-foreground">
            <ShieldCheck class="w-14 h-14 mx-auto mb-4 opacity-40" />
            <p class="text-lg font-medium">No threats detected</p>
            <p class="text-sm mt-1">All analyzed items appear to be safe</p>
          </div>
        </div>
      </section>

      <!-- Message Content with Views -->
      <section class="glass-panel rounded-xl mb-10">
        <div class="p-5 border-b border-border/40 flex items-center justify-between">
          <h2 class="font-semibold">Message Content</h2>
        </div>
        <table class="w-full">
          <tbody class="divide-y divide-border/30">
            <tr>
              <td class="p-4 text-sm text-muted-foreground w-32 lg:w-40 align-top">Subject</td>
              <td class="p-4 text-sm">{{ emailContent?.subject || 'No Subject' }}</td>
            </tr>
            <tr v-if="senderDetails">
              <td class="p-4 text-sm text-muted-foreground align-top">Sender</td>
              <td class="p-4 text-sm">
                <span class="text-primary">{{ senderDetails.displayName || '' }}</span>
                <span class="text-muted-foreground">&lt;{{ senderDetails.email || 'unknown' }}&gt;</span>
              </td>
            </tr>
            <tr v-if="emailContent?.returnPath">
              <td class="p-4 text-sm text-muted-foreground align-top">Return Path</td>
              <td class="p-4 text-sm font-mono text-xs">{{ emailContent.returnPath }}</td>
            </tr>
            <tr>
              <td class="p-4 text-sm text-muted-foreground align-top">To</td>
              <td class="p-4 text-sm">{{ emailContent?.to || 'Unknown' }}</td>
            </tr>
            <tr v-if="emailContent?.cc">
              <td class="p-4 text-sm text-muted-foreground align-top">CC</td>
              <td class="p-4 text-sm">{{ emailContent.cc }}</td>
            </tr>
            <tr v-if="emailContent?.bcc">
              <td class="p-4 text-sm text-muted-foreground align-top">BCC</td>
              <td class="p-4 text-sm">{{ emailContent.bcc }}</td>
            </tr>
            <tr v-if="attachmentSummary && attachmentSummary.total > 0">
              <td class="p-4 text-sm text-muted-foreground align-top">Attachments</td>
              <td class="p-4 text-sm">
                <div class="flex flex-wrap gap-x-3 gap-y-1">
                  <span v-for="(attachment, idx) in attachmentSummary.samples" :key="idx"
                    class="inline-flex items-center gap-1">
                    <a href="#attachments" @click.prevent="scrollToAttachments" class="text-primary hover:underline">{{
                      attachment.filename }}</a>
                  </span>
                </div>
              </td>
            </tr>
            <tr v-if="emailContent?.date">
              <td class="p-4 text-sm text-muted-foreground align-top">Received</td>
              <td class="p-4 text-sm">{{ emailContent.date }}</td>
            </tr>
            <tr>
              <td class="p-4 text-sm text-muted-foreground align-top">Type</td>
              <td class="p-4 text-sm">Inbound</td>
            </tr>
          </tbody>
        </table>

        <!-- Tab Navigation -->
        <div class="flex items-center justify-between border-t border-b border-border/40">
          <div class="flex overflow-x-auto">
            <button @click="activeMessageTab = 'user'" :class="[
              'px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap border-b-2',
              activeMessageTab === 'user'
                ? 'border-primary text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            ]">
              User View
            </button>
            <button @click="activeMessageTab = 'text'" :class="[
              'px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap border-b-2',
              activeMessageTab === 'text'
                ? 'border-primary text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            ]">
              Text View
            </button>
            <button @click="activeMessageTab = 'html'" :class="[
              'px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap border-b-2',
              activeMessageTab === 'html'
                ? 'border-primary text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            ]">
              HTML View
            </button>
            <button @click="activeMessageTab = 'eml'" :class="[
              'px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap border-b-2',
              activeMessageTab === 'eml'
                ? 'border-primary text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            ]">
              EML View
            </button>
            <button @click="activeMessageTab = 'mdm'" :class="[
              'px-4 py-3 text-sm font-medium transition-colors whitespace-nowrap border-b-2',
              activeMessageTab === 'mdm'
                ? 'border-primary text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            ]">
              MDM View
            </button>
          </div>
          <!-- Download EML Button -->
          <button v-if="rawEmlContent" @click="downloadEml"
            class="flex items-center gap-2 px-4 py-2 mr-2 text-sm text-muted-foreground hover:text-foreground transition-colors">
            Download EML
            <Download class="w-4 h-4" />
          </button>
        </div>

        <!-- Tab Content -->
        <div class="p-4">
          <!-- User View - Rendered HTML Email -->
          <div v-if="activeMessageTab === 'user'">
            <div v-if="rawHtmlBody" class="bg-white rounded-lg p-4 max-h-[500px] overflow-y-auto">
              <div v-html="sanitizedHtml" class="prose prose-sm max-w-none"></div>
            </div>
            <div v-else-if="rawTextBody" class="bg-card/50 rounded-lg p-4 max-h-[500px] overflow-y-auto">
              <pre class="text-sm whitespace-pre-wrap break-words text-foreground">{{ rawTextBody }}</pre>
            </div>
            <div v-else class="text-center py-12 text-muted-foreground">
              <Mail class="w-12 h-12 mx-auto mb-3 opacity-40" />
              <p class="text-sm">No email content available</p>
            </div>
          </div>

          <!-- Text View - Plain Text Body -->
          <div v-else-if="activeMessageTab === 'text'">
            <div v-if="rawTextBody"
              class="relative border border-border/40 rounded-lg p-4 max-h-[500px] overflow-y-auto">
              <button @click="copyTextBody"
                class="absolute top-3 right-3 z-10 p-2 bg-muted hover:bg-muted/80 rounded-lg transition-colors">
                <Check v-if="copiedTextBody" class="w-4 h-4 text-emerald-500" />
                <Copy v-else class="w-4 h-4 text-muted-foreground" />
              </button>
              <pre class="text-sm font-mono text-foreground whitespace-pre-wrap break-words">{{ rawTextBody }}</pre>
            </div>
            <div v-else class="text-center py-12 text-muted-foreground">
              <FileText class="w-12 h-12 mx-auto mb-3 opacity-40" />
              <p class="text-sm">No plain text content available</p>
            </div>
          </div>

          <!-- HTML View - Raw HTML Source -->
          <div v-else-if="activeMessageTab === 'html'">
            <div v-if="rawHtmlBody"
              class="relative border border-border/40 rounded-lg p-4 max-h-[500px] overflow-y-auto">
              <button @click="copyHtmlBody"
                class="absolute top-3 right-3 z-10 p-2 bg-muted hover:bg-muted/80 rounded-lg transition-colors">
                <Check v-if="copiedHtmlBody" class="w-4 h-4 text-emerald-500" />
                <Copy v-else class="w-4 h-4 text-muted-foreground" />
              </button>
              <pre class="text-sm font-mono text-foreground whitespace-pre-wrap break-words">{{ rawHtmlBody }}</pre>
            </div>
            <div v-else class="text-center py-12 text-muted-foreground">
              <Code class="w-12 h-12 mx-auto mb-3 opacity-40" />
              <p class="text-sm">No HTML content available</p>
            </div>
          </div>

          <!-- EML View - Raw EML Content -->
          <div v-else-if="activeMessageTab === 'eml'">
            <div v-if="rawEmlContent"
              class="relative border border-border/40 rounded-lg p-4 max-h-[500px] overflow-y-auto">
              <button @click="copyEmlContent"
                class="absolute top-3 right-3 z-10 p-2 bg-muted hover:bg-muted/80 rounded-lg transition-colors">
                <Check v-if="copiedEmlContent" class="w-4 h-4 text-emerald-500" />
                <Copy v-else class="w-4 h-4 text-muted-foreground" />
              </button>
              <pre class="text-sm font-mono text-foreground whitespace-pre-wrap break-words">{{ rawEmlContent }}</pre>
            </div>
            <div v-else class="text-center py-12 text-muted-foreground">
              <FileCode class="w-12 h-12 mx-auto mb-3 opacity-40" />
              <p class="text-sm">Raw EML content not available</p>
            </div>
          </div>

          <!-- MDM View - Sublime MDM JSON with Recursive Collapsible Tree -->
          <div v-else-if="activeMessageTab === 'mdm'">
            <div v-if="mdmData" class="relative border border-border/40 rounded-lg p-4 max-h-[500px] overflow-y-auto">
              <button @click="copyMdmData"
                class="absolute top-3 right-3 z-10 p-2 bg-muted hover:bg-muted/80 rounded-lg transition-colors">
                <Check v-if="copiedMdmData" class="w-4 h-4 text-emerald-500" />
                <Copy v-else class="w-4 h-4 text-muted-foreground" />
              </button>
              <div class="text-sm font-mono pr-10">
                <!-- Recursive JSON Tree -->
                <template v-for="(value, key) in mdmData" :key="`mdm.${key}`">
                  <div class="py-0.5">
                    <!-- Object/Array - Collapsible -->
                    <template v-if="value !== null && typeof value === 'object'">
                      <button @click="toggleJsonNode(`mdm.${key}`)"
                        class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                        <ChevronRight class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                          :class="{ 'rotate-90': isJsonNodeExpanded(`mdm.${key}`) }" />
                        <span class="text-foreground">{{ key }}:</span>
                        <span class="text-muted-foreground">{{ getItemLabel(value) }}</span>
                      </button>
                      <!-- Level 2 -->
                      <div v-if="isJsonNodeExpanded(`mdm.${key}`)" class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                        <template v-for="(val2, key2) in (value as object)" :key="`mdm.${key}.${key2}`">
                          <div class="py-0.5">
                            <template v-if="val2 !== null && typeof val2 === 'object'">
                              <button @click="toggleJsonNode(`mdm.${key}.${key2}`)"
                                class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                <ChevronRight class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                  :class="{ 'rotate-90': isJsonNodeExpanded(`mdm.${key}.${key2}`) }" />
                                <span class="text-foreground">{{ key2 }}:</span>
                                <span class="text-muted-foreground">{{ getItemLabel(val2) }}</span>
                              </button>
                              <!-- Level 3 -->
                              <div v-if="isJsonNodeExpanded(`mdm.${key}.${key2}`)"
                                class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                <template v-for="(val3, key3) in (val2 as object)" :key="`mdm.${key}.${key2}.${key3}`">
                                  <div class="py-0.5">
                                    <template v-if="val3 !== null && typeof val3 === 'object'">
                                      <button @click="toggleJsonNode(`mdm.${key}.${key2}.${key3}`)"
                                        class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                        <ChevronRight
                                          class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                          :class="{ 'rotate-90': isJsonNodeExpanded(`mdm.${key}.${key2}.${key3}`) }" />
                                        <span class="text-foreground">{{ key3 }}:</span>
                                        <span class="text-muted-foreground">{{ getItemLabel(val3) }}</span>
                                      </button>
                                      <!-- Level 4+ - Show as JSON -->
                                      <div v-if="isJsonNodeExpanded(`mdm.${key}.${key2}.${key3}`)"
                                        class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                        <pre
                                          class="text-foreground whitespace-pre-wrap break-words text-xs">{{ prettyJson(val3) }}</pre>
                                      </div>
                                    </template>
                                    <template v-else>
                                      <div class="flex items-start gap-1.5 pl-4">
                                        <span class="text-foreground shrink-0">{{ key3 }}:</span>
                                        <span class="text-muted-foreground ml-1 break-all">{{ val3 === null ? 'null' :
                                          val3 }}</span>
                                      </div>
                                    </template>
                                  </div>
                                </template>
                              </div>
                            </template>
                            <template v-else>
                              <div class="flex items-start gap-1.5 pl-4">
                                <span class="text-foreground shrink-0">{{ key2 }}:</span>
                                <span class="text-muted-foreground ml-1 break-all">{{ val2 === null ? 'null' : val2
                                }}</span>
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
                        <span class="text-muted-foreground ml-1 break-all">{{ value === null ? 'null' : value }}</span>
                      </div>
                    </template>
                  </div>
                </template>
              </div>
            </div>
            <div v-else class="text-center py-12 text-muted-foreground">
              <Database class="w-12 h-12 mx-auto mb-3 opacity-40" />
              <p class="text-sm">No MDM data available</p>
            </div>
          </div>
        </div>
      </section>

      <!-- Errors -->
      <div class="mb-10">
        <section v-if="Object.keys(analysisResult?.sublime.errors ?? {}).length"
          class="glass-panel rounded-xl border-destructive/30">
          <div class="p-4 bg-destructive/10 border-b border-destructive/20">
            <h2 class="text-sm font-semibold text-destructive flex items-center gap-2">
              <XCircle class="w-4 h-4" /> Errors
            </h2>
          </div>
          <div class="p-4 space-y-2">
            <div v-for="(message, key) in analysisResult?.sublime.errors" :key="key" class="text-xs">
              <span class="font-bold">{{ key }}:</span>
              <span class="text-muted-foreground ml-1">{{ message }}</span>
            </div>
          </div>
        </section>
      </div>

      <!-- Raw Analysis Data -->
      <section class="glass-panel rounded-xl mb-10">
        <button @click="rawDataExpanded = !rawDataExpanded"
          class="w-full p-5 flex items-center justify-between hover:bg-card/30 transition-colors border-b border-border/40">
          <div class="flex items-center gap-3">
            <div class="p-2 bg-primary/10 rounded-lg">
              <FileCode class="w-5 h-5 text-primary" />
            </div>
            <div class="text-left">
              <h2 class="font-semibold">Raw Analysis Data</h2>
              <p class="text-sm text-muted-foreground">Complete JSON response from all sources</p>
            </div>
          </div>
          <ChevronDown v-if="!rawDataExpanded" class="w-5 h-5 text-muted-foreground" />
          <ChevronDown v-else class="w-5 h-5 text-muted-foreground rotate-180 transition-transform" />
        </button>

        <div v-if="rawDataExpanded" class="p-5">
          <div class="relative">
            <button @click="copyRawData"
              class="absolute top-3 right-3 z-10 p-2 bg-muted hover:bg-muted/80 rounded-lg transition-colors">
              <Check v-if="copiedRawData" class="w-4 h-4 text-emerald-500" />
              <Copy v-else class="w-4 h-4 text-muted-foreground" />
            </button>
            <div class="border border-border/40 rounded-xl p-4 overflow-auto max-h-[500px] text-sm font-mono">
              <!-- JSON Tree View - Same pattern as MDM View -->
              <template v-for="(value, key) in filteredAnalysisResult" :key="`raw.${key}`">
                <div class="py-0.5">
                  <!-- Object/Array - Collapsible -->
                  <template v-if="value !== null && typeof value === 'object'">
                    <button @click="toggleJsonNode(`raw.${key}`)"
                      class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                      <ChevronRight class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                        :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}`) }" />
                      <span class="text-foreground">{{ key }}:</span>
                      <span class="text-muted-foreground">{{ getItemLabel(value) }}</span>
                    </button>
                    <!-- Level 2 -->
                    <div v-if="isJsonNodeExpanded(`raw.${key}`)" class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                      <template v-for="(val2, key2) in (value as object)" :key="`raw.${key}.${key2}`">
                        <div class="py-0.5">
                          <template v-if="val2 !== null && typeof val2 === 'object'">
                            <button @click="toggleJsonNode(`raw.${key}.${key2}`)"
                              class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                              <ChevronRight class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}.${key2}`) }" />
                              <span class="text-foreground">{{ key2 }}:</span>
                              <span class="text-muted-foreground">{{ getItemLabel(val2) }}</span>
                            </button>
                            <!-- Level 3 -->
                            <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}`)"
                              class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                              <template v-for="(val3, key3) in (val2 as object)" :key="`raw.${key}.${key2}.${key3}`">
                                <div class="py-0.5">
                                  <template v-if="val3 !== null && typeof val3 === 'object'">
                                    <button @click="toggleJsonNode(`raw.${key}.${key2}.${key3}`)"
                                      class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                      <ChevronRight class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                        :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}.${key2}.${key3}`) }" />
                                      <span class="text-foreground">{{ key3 }}:</span>
                                      <span class="text-muted-foreground">{{ getItemLabel(val3) }}</span>
                                    </button>
                                    <!-- Level 4 -->
                                    <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}.${key3}`)"
                                      class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                      <template v-for="(val4, key4) in (val3 as object)" :key="`raw.${key}.${key2}.${key3}.${key4}`">
                                        <div class="py-0.5">
                                          <template v-if="val4 !== null && typeof val4 === 'object'">
                                            <button @click="toggleJsonNode(`raw.${key}.${key2}.${key3}.${key4}`)"
                                              class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                              <ChevronRight class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
                                                :class="{ 'rotate-90': isJsonNodeExpanded(`raw.${key}.${key2}.${key3}.${key4}`) }" />
                                              <span class="text-foreground">{{ key4 }}:</span>
                                              <span class="text-muted-foreground">{{ getItemLabel(val4) }}</span>
                                            </button>
                                            <!-- Level 5 -->
                                            <div v-if="isJsonNodeExpanded(`raw.${key}.${key2}.${key3}.${key4}`)"
                                              class="pl-4 border-l border-border/40 ml-1.5 mt-0.5">
                                              <template v-for="(val5, key5) in (val4 as object)" :key="`raw.${key}.${key2}.${key3}.${key4}.${key5}`">
                                                <div class="py-0.5">
                                                  <template v-if="val5 !== null && typeof val5 === 'object'">
                                                    <button @click="toggleJsonNode(`raw.${key}.${key2}.${key3}.${key4}.${key5}`)"
                                                      class="flex items-center gap-1.5 hover:bg-muted/50 rounded px-1 -ml-1 text-left py-0.5">
                                                      <ChevronRight class="w-3 h-3 text-muted-foreground transition-transform shrink-0"
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
                                      <span class="text-foreground shrink-0">{{ key3 }}:</span>
                                      <span class="text-muted-foreground ml-1 break-all">{{ val3 === null ? 'null' : val3 }}</span>
                                    </div>
                                  </template>
                                </div>
                              </template>
                            </div>
                          </template>
                          <template v-else>
                            <div class="flex items-start gap-1.5 pl-4">
                              <span class="text-foreground shrink-0">{{ key2 }}:</span>
                              <span class="text-muted-foreground ml-1 break-all">{{ val2 === null ? 'null' : val2 }}</span>
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
                      <span class="text-muted-foreground ml-1 break-all">{{ value === null ? 'null' : value }}</span>
                    </div>
                  </template>
                </div>
              </template>
            </div>
          </div>
        </div>
      </section>
    </div>
  </main>

  <!-- Insight Detail Dialog -->
  <Dialog v-model:open="insightDetailOpen">
    <DialogContent class="max-w-md max-h-[80vh] flex flex-col">
      <DialogHeader class="shrink-0">
        <DialogTitle class="flex items-center gap-2">
          <Lightbulb class="w-5 h-5 text-yellow-500 shrink-0" />
          <span class="break-words">{{ selectedInsight?.title }}</span>
        </DialogTitle>
        <span v-if="selectedInsight?.severity"
          class="inline-flex w-fit px-2 py-0.5 rounded text-xs font-medium uppercase mt-2" :class="{
            'bg-destructive/20 text-destructive': selectedInsight.severity === 'HIGH',
            'bg-yellow-500/20 text-yellow-600': selectedInsight.severity === 'MEDIUM',
            'bg-blue-500/20 text-blue-600': selectedInsight.severity === 'LOW',
            'bg-muted text-muted-foreground': selectedInsight.severity === 'INFO'
          }">{{ selectedInsight.severity }}</span>
      </DialogHeader>

      <div class="flex-1 overflow-y-auto space-y-2 py-4">
        <div v-for="(text, idx) in (selectedInsight ? getInsightDetailItems(selectedInsight) : [])" :key="idx"
          class="flex items-start justify-between gap-2 p-3 bg-muted/50 rounded-lg group overflow-hidden">
          <p class="text-sm break-all flex-1 font-mono min-w-0 overflow-hidden">{{ text }}</p>
          <button @click="copyInsightItem(text)" class="p-1.5 rounded hover:bg-muted transition-colors shrink-0">
            <Check v-if="copiedInsightItem === text" class="w-4 h-4 text-emerald-500" />
            <Copy v-else class="w-4 h-4 text-muted-foreground" />
          </button>
        </div>
      </div>

      <!-- Copy All button at bottom right -->
      <div class="flex justify-end pt-2 border-t border-border shrink-0">
        <button @click="copyInsightAll"
          class="flex items-center gap-2 px-3 py-1.5 rounded hover:bg-muted transition-colors text-sm" title="Copy All">
          <Check v-if="copiedInsightAll" class="w-4 h-4 text-emerald-500" />
          <Copy v-else class="w-4 h-4 text-muted-foreground" />
          <span>{{ copiedInsightAll ? 'Copied!' : 'Copy All' }}</span>
        </button>
      </div>
    </DialogContent>
  </Dialog>

  <!-- Rule Detail Dialog with Tree View -->
  <Dialog v-model:open="ruleDetailOpen">
    <DialogContent class="max-w-xl max-h-[80vh] flex flex-col">
      <DialogHeader class="shrink-0">
        <DialogTitle class="flex items-center gap-2">
          <ShieldAlert class="w-5 h-5 text-primary shrink-0" />
          <span class="break-words">{{ selectedRule?.title }}</span>
        </DialogTitle>
        <span v-if="selectedRule?.severity"
          class="inline-flex w-fit px-2 py-0.5 rounded text-xs font-medium uppercase mt-2" :class="{
            'bg-destructive/20 text-destructive': selectedRule.severity === 'HIGH' || selectedRule.severity === 'CRITICAL',
            'bg-yellow-500/20 text-yellow-600': selectedRule.severity === 'MEDIUM',
            'bg-blue-500/20 text-blue-600': selectedRule.severity === 'LOW',
            'bg-muted text-muted-foreground': selectedRule.severity === 'INFO'
          }">{{ selectedRule.severity }}</span>
      </DialogHeader>

      <div class="flex-1 overflow-y-auto py-4">
        <div class="p-3 bg-muted/50 rounded-lg overflow-hidden text-sm font-mono" v-if="selectedRule?.raw">
          <!-- Tree view for rule data -->
          <template v-if="(selectedRule.raw as Record<string, unknown>)['rule']">
            <!-- Rule object header -->
            <div class="flex items-center gap-1 cursor-pointer hover:bg-muted rounded px-1 -mx-1"
              @click="toggleRuleTreeNode('rule')">
              <ChevronRight class="w-4 h-4 transition-transform shrink-0"
                :class="{ 'rotate-90': isRuleTreeExpanded('rule') }" />
              <span>rule {{ isRuleTreeExpanded('rule') ? '{' : '{...}' }}</span>
            </div>
            <div v-if="isRuleTreeExpanded('rule')" class="pl-6 border-l border-border/50 ml-2 space-y-1">
              <!-- Rule ID -->
              <div v-if="((selectedRule.raw as Record<string, unknown>)['rule'] as Record<string, unknown>)?.['id']"
                class="py-0.5">
                <span>id: </span>
                <span>"{{ ((selectedRule.raw as Record<string, unknown>)['rule'] as Record<string, unknown>)['id']
                      }}"</span>
              </div>
              <!-- Rule Name -->
              <div v-if="((selectedRule.raw as Record<string, unknown>)['rule'] as Record<string, unknown>)?.['name']"
                class="py-0.5">
                <span>name: </span>
                <span class="break-words">"{{ ((selectedRule.raw as Record<string, unknown>)['rule'] as Record<string,
                  unknown>)['name'] }}"</span>
              </div>
              <!-- Source (Detection Logic) - collapsible -->
              <div
                v-if="((selectedRule.raw as Record<string, unknown>)['rule'] as Record<string, unknown>)?.['source']">
                <div class="flex items-center gap-1 cursor-pointer hover:bg-muted rounded px-1 -mx-1"
                  @click="toggleRuleTreeNode('rule.source')">
                  <ChevronRight class="w-4 h-4 transition-transform shrink-0"
                    :class="{ 'rotate-90': isRuleTreeExpanded('rule.source') }" />
                  <span>source: </span>
                  <span v-if="!isRuleTreeExpanded('rule.source')" class="text-muted-foreground truncate">"{{
                    (((selectedRule.raw as Record<string, unknown>)['rule'] as Record<string, unknown>)['source'] as
                      string).substring(0, 25) }}..."</span>
                </div>
                <div v-if="isRuleTreeExpanded('rule.source')" class="pl-6 py-1 border-l border-border/50 ml-2">
                  <pre
                    class="text-xs whitespace-pre-wrap leading-relaxed">{{ ((selectedRule.raw as Record<string, unknown>)['rule'] as Record<string, unknown>)['source'] }}</pre>
                </div>
              </div>
              <!-- Severity -->
              <div
                v-if="((selectedRule.raw as Record<string, unknown>)['rule'] as Record<string, unknown>)?.['severity']"
                class="py-0.5">
                <span>severity: </span>
                <span>"{{ ((selectedRule.raw as Record<string, unknown>)['rule'] as Record<string, unknown>)['severity']
                      }}"</span>
              </div>
            </div>
            <div v-if="isRuleTreeExpanded('rule')">}</div>
          </template>

          <!-- Other fields -->
          <div v-if="(selectedRule.raw as Record<string, unknown>)['matched'] !== undefined" class="py-0.5">
            <span>matched: </span>
            <span>{{ (selectedRule.raw as Record<string, unknown>)['matched'] }}</span>
          </div>
          <div v-if="(selectedRule.raw as Record<string, unknown>)['success'] !== undefined" class="py-0.5">
            <span>success: </span>
            <span>{{ (selectedRule.raw as Record<string, unknown>)['success'] }}</span>
          </div>
          <div v-if="(selectedRule.raw as Record<string, unknown>)['error'] !== undefined" class="py-0.5">
            <span>error: </span>
            <span>{{ (selectedRule.raw as Record<string, unknown>)['error'] === null ? 'null' : (selectedRule.raw as
              Record<string, unknown>)['error'] }}</span>
          </div>
          <div v-if="(selectedRule.raw as Record<string, unknown>)['execution_time'] !== undefined" class="py-0.5">
            <span>execution_time: </span>
            <span>{{ (selectedRule.raw as Record<string, unknown>)['execution_time'] }}</span>
          </div>
        </div>
      </div>

      <!-- Copy All button at bottom right -->
      <div class="flex justify-end pt-2 border-t border-border shrink-0">
        <button @click="copyRuleDetail"
          class="flex items-center gap-2 px-3 py-1.5 rounded hover:bg-muted transition-colors text-sm" title="Copy All">
          <Check v-if="copiedRuleDetail" class="w-4 h-4 text-emerald-500" />
          <Copy v-else class="w-4 h-4 text-muted-foreground" />
          <span>{{ copiedRuleDetail ? 'Copied!' : 'Copy All' }}</span>
        </button>
      </div>
    </DialogContent>
  </Dialog>
</template>

<style>
::-webkit-scrollbar {
  width: 6px;
  height: 6px;
}

::-webkit-scrollbar-track {
  background: transparent;
}

::-webkit-scrollbar-thumb {
  background: hsl(var(--muted));
  border-radius: 3px;
}

::-webkit-scrollbar-thumb:hover {
  background: hsl(var(--muted-foreground));
}

@keyframes shimmer {
  0% {
    transform: translateX(-100%);
  }

  100% {
    transform: translateX(100%);
  }
}
</style>
