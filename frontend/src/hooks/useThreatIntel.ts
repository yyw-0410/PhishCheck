import { computed, ref, watch, onUnmounted } from 'vue'
import type { Ref } from 'vue'

import type {
  CombinedAnalysisResult,
  UrlscanSubmission,
  VirusTotalEngine,
  VirusTotalLookup,
  VTSummary,
  IPQSLookup,
  HybridAnalysisLookup,
} from '@/types/analysis'
import { useAnalysisStore } from '@/stores/analysis'
import { isVerdictPending, capitalizeFirst } from '@/utils/screenshotUtils'

type VTSortKey = 'engine' | 'category' | 'result'

import { API_BASE_URL } from '@/services/api'

const VT_WEIGHT: Record<string, number> = {
  malicious: 0,
  suspicious: 1,
  timeout: 2,
  failure: 2,
  'confirmed-timeout': 2,
  'type-unsupported': 3,
  undetected: 4,
  harmless: 5,
  unknown: 6,
}

const VT_CATEGORIES = ['ALL', 'malicious', 'suspicious', 'harmless', 'undetected', 'timeout', 'unknown'] as const

export function useThreatIntel(analysisResult: Ref<CombinedAnalysisResult | null>) {
  const expandedVirusTotalIndicators = ref<Record<string, boolean>>({})
  const vtSortState = ref<Record<string, { key: VTSortKey; dir: 'asc' | 'desc' }>>({})
  const vtFilterState = ref<Record<string, string>>({})
  const vtGlobalFilter = ref<'ALL' | 'RISKY' | 'CLEAN'>('ALL')

  const copiedTargets = ref<Record<number, boolean>>({})
  const urlscanImageLoaded = ref<Record<string, boolean>>({})

  const severityOrder: Record<string, number> = {
    malicious: 0,
    suspicious: 1,
    timeout: 2,
    failure: 2,
    'confirmed-timeout': 2,
    'type-unsupported': 3,
    undetected: 4,
    harmless: 5,
    unknown: 6,
  }

  const weightCategory = (raw?: string) => severityOrder[raw ?? 'unknown'] ?? 6

  const buildSummary = (lookup: VirusTotalLookup): VTSummary => {
    const attributes = lookup.data?.attributes as Record<string, unknown> | undefined
    const id = lookup.data?.id as string | undefined
    const stats = attributes?.last_analysis_stats as Record<string, number> | undefined
    const results = attributes?.last_analysis_results as Record<string, { category?: string; result?: string }> | undefined

    const summaryStats = {
      harmless: stats?.harmless ?? 0,
      malicious: stats?.malicious ?? 0,
      suspicious: stats?.suspicious ?? 0,
      undetected: stats?.undetected ?? 0,
      timeout: stats?.timeout ?? 0,
    }

    const engines: VirusTotalEngine[] = results
      ? Object.entries(results).map(([engine, detail]) => ({
        engine,
        category: detail?.category ?? detail?.result ?? 'unknown',
        result: detail?.result ?? '',
      }))
      : []

    engines.sort((a, b) => weightCategory(a.category) - weightCategory(b.category) || a.engine.localeCompare(b.engine))

    const verdict =
      summaryStats.malicious > 0
        ? 'Malicious'
        : summaryStats.suspicious > 0
          ? 'Suspicious'
          : summaryStats.harmless > 0 && summaryStats.undetected === 0
            ? 'Harmless'
            : 'No detections'

    const verdictClass =
      verdict === 'Malicious' ? 'danger' : verdict === 'Suspicious' ? 'warn' : verdict === 'Harmless' ? 'ok' : 'info'

    const total =
      summaryStats.harmless +
      summaryStats.malicious +
      summaryStats.suspicious +
      summaryStats.undetected +
      summaryStats.timeout

    return {
      indicator: lookup.indicator,
      indicator_type: lookup.indicator_type,
      id,
      stats: summaryStats,
      total,
      engines,
      error: lookup.error ?? null,
      verdict,
      verdictClass,
      sources: Array.isArray(lookup.sources) ? lookup.sources : [],
    }
  }

  const virusTotalSummaries = computed(() => {
    const lookups = analysisResult.value?.threat_intel?.virustotal ?? []
    return lookups.map((lookup) => buildSummary(lookup))
  })

  const vtIndicatorBuckets = computed(() => {
    const buckets = { malicious: 0, suspicious: 0, clean: 0, none: 0, total: 0 }
    for (const summary of virusTotalSummaries.value) {
      buckets.total += 1
      if (summary.verdict === 'Malicious') buckets.malicious += 1
      else if (summary.verdict === 'Suspicious') buckets.suspicious += 1
      else if (summary.verdict === 'Harmless') buckets.clean += 1
      else buckets.none += 1
    }
    return buckets
  })

  const vtFilteredSummaries = computed(() => {
    switch (vtGlobalFilter.value) {
      case 'RISKY':
        return virusTotalSummaries.value.filter(
          (summary) => summary.verdict === 'Malicious' || summary.verdict === 'Suspicious',
        )
      case 'CLEAN':
        return virusTotalSummaries.value.filter(
          (summary) => summary.verdict === 'Harmless' || summary.verdict === 'No detections',
        )
      default:
        return virusTotalSummaries.value
    }
  })

  const getVtFilter = (indicator: string) => vtFilterState.value[indicator] ?? 'ALL'
  const setVtFilter = (indicator: string, value: string) => {
    vtFilterState.value[indicator] = value
  }

  const setVtSort = (indicator: string, key: VTSortKey) => {
    const state = vtSortState.value[indicator]
    if (!state || state.key !== key) {
      vtSortState.value[indicator] = { key, dir: 'asc' }
    } else {
      vtSortState.value[indicator] = { key, dir: state.dir === 'asc' ? 'desc' : 'asc' }
    }
  }

  const sortGlyph = (indicator: string, key: VTSortKey) => {
    const state = vtSortState.value[indicator]
    if (!state || state.key !== key) return ''
    return state.dir === 'asc' ? '^' : 'v'
  }

  const vtViewEngines = (indicator: string, engines: VirusTotalEngine[]) => {
    const filter = getVtFilter(indicator)
    let list =
      filter === 'ALL'
        ? [...engines]
        : engines.filter((engine) => (engine.category || 'unknown').toLowerCase() === filter.toLowerCase())

    const state = vtSortState.value[indicator]
    if (!state) return list

    const { key, dir } = state
    const comparator = (a: VirusTotalEngine, b: VirusTotalEngine) => {
      if (key === 'category') {
        const aw = VT_WEIGHT[(a.category || 'unknown').toLowerCase()] ?? 6
        const bw = VT_WEIGHT[(b.category || 'unknown').toLowerCase()] ?? 6
        if (aw !== bw) return aw - bw
        return a.engine.localeCompare(b.engine)
      }
      const aValue = (a[key] || '').toLowerCase()
      const bValue = (b[key] || '').toLowerCase()
      return aValue.localeCompare(bValue)
    }

    list.sort(comparator)
    if (dir === 'desc') list.reverse()
    return list
  }

  const toggleVirusTotalEngines = (indicator: string) => {
    expandedVirusTotalIndicators.value[indicator] = !expandedVirusTotalIndicators.value[indicator]
  }

  const isVirusTotalExpanded = (indicator: string) => Boolean(expandedVirusTotalIndicators.value[indicator])

  const copiedHashes = ref<Record<string, boolean>>({})

  const copyHash = async (hash: string) => {
    if (!hash) return
    try {
      await navigator.clipboard.writeText(hash)
      copiedHashes.value[hash] = true
      window.setTimeout(() => {
        copiedHashes.value[hash] = false
      }, 1500)
    } catch (error) {
      console.warn('Clipboard write failed', error)
    }
  }

  const openVtForFile = (sha256: string) => {
    if (!sha256) return
    window.open(`https://www.virustotal.com/gui/file/${sha256}`, '_blank')
  }

  const copyTarget = async (index: number, value: string | null | undefined) => {
    if (!value) return
    try {
      await navigator.clipboard.writeText(value)
      copiedTargets.value[index] = true
      window.setTimeout(() => {
        copiedTargets.value[index] = false
      }, 1500)
    } catch (error) {
      console.warn('Clipboard write failed', error)
    }
  }

  const formatUrl = (value?: string | null) => {
    const raw = typeof value === 'string' ? value.trim() : ''
    if (!raw) return 'URL unavailable'
    try {
      const url = new URL(raw)
      const host = url.hostname.replace(/^www\./, '')
      const path = url.pathname === '/' ? '' : url.pathname
      return `${host}${path}`
    } catch {
      return raw.length > 80 ? `${raw.slice(0, 77)}...` : raw
    }
  }

  const urlscanVerdict = (scan: UrlscanSubmission) => {
    if (scan.error) return 'Failed'
    // Use the backend-provided verdict if set (most reliable)
    if (scan.verdict && !isVerdictPending(scan.verdict)) {
      return capitalizeFirst(scan.verdict)
    }
    // If we have a result_url, scan completed - check if verdict is set
    if (scan.result_url) {
      // Verdict might not be set yet, but scan completed
      return scan.verdict ? capitalizeFirst(scan.verdict) : 'Completed'
    }
    // No result_url means scan is still pending
    return 'Pending'
  }

  const urlscanSubmissions = computed(() => analysisResult.value?.threat_intel.urlscan ?? [])

  // IPQS IP reputation results
  const ipqsResults = computed<IPQSLookup[]>(() => analysisResult.value?.threat_intel.ipqs ?? [])

  // Hybrid Analysis sandbox results
  const hybridAnalysisResults = computed<HybridAnalysisLookup[]>(
    () => analysisResult.value?.threat_intel.hybrid_analysis ?? []
  )

  const urlscanCompletedSubmissions = computed(() => {
    const scans = analysisResult.value?.threat_intel.urlscan ?? []
    return scans.filter((scan) => urlscanVerdict(scan) === 'Completed')
  })

  const refreshingScans = ref<Record<string, boolean>>({})
  const refreshErrors = ref<Record<string, string | null>>({})

  watch(
    () => analysisResult.value?.threat_intel.urlscan,
    (next) => {
      copiedTargets.value = {}
      if (!next) {
        urlscanImageLoaded.value = {}
        return
      }
      const prev = urlscanImageLoaded.value
      const nextState: Record<string, boolean> = {}
      next.forEach((scan, index) => {
        const key = urlscanKey(scan, index)
        nextState[key] = prev[key] ?? false
      })
      urlscanImageLoaded.value = nextState
    },
  )

  watch(
    () => analysisResult.value?.threat_intel.virustotal,
    () => {
      expandedVirusTotalIndicators.value = {}
      vtFilterState.value = {}
      vtSortState.value = {}
    },
  )

  const vtSummaryCard = computed(() => {
    const total = virusTotalSummaries.value.length
    if (!total) return null
    const buckets = vtIndicatorBuckets.value
    return {
      total,
      malicious: buckets.malicious,
      suspicious: buckets.suspicious,
      clean: buckets.clean,
      none: buckets.none,
    }
  })

  // Breakdown by type (domain vs file)
  const vtByType = computed(() => {
    const domains = virusTotalSummaries.value.filter(s => s.indicator_type === 'domain')
    const files = virusTotalSummaries.value.filter(s => s.indicator_type === 'file')
    const urls = virusTotalSummaries.value.filter(s => s.indicator_type === 'url')
    return {
      domainCount: domains.length,
      fileCount: files.length,
      urlCount: urls.length,
      domainMalicious: domains.filter(s => s.verdict === 'Malicious').length,
      fileMalicious: files.filter(s => s.verdict === 'Malicious').length,
      urlMalicious: urls.filter(s => s.verdict === 'Malicious').length,
      domainSuspicious: domains.filter(s => s.verdict === 'Suspicious').length,
      fileSuspicious: files.filter(s => s.verdict === 'Suspicious').length,
      domains,
      files,
    }
  })

  // Get VT result for a specific file by SHA256
  const getVtResultForFile = (sha256: string | undefined) => {
    if (!sha256) return null
    const normalized = sha256.toLowerCase()
    return virusTotalSummaries.value.find(
      s => s.indicator_type === 'file' && s.indicator.toLowerCase() === normalized
    ) || null
  }

  // Get flagged items (malicious or suspicious) - only domains/URLs, not files
  // Files are shown in File Attachments section with their VT verdict
  const vtFlaggedItems = computed(() => {
    return virusTotalSummaries.value
      .filter(s => (s.verdict === 'Malicious' || s.verdict === 'Suspicious') && s.indicator_type !== 'file')
      .map(s => ({
        indicator: s.indicator,
        type: s.indicator_type,
        verdict: s.verdict,
        maliciousCount: s.stats.malicious,
        suspiciousCount: s.stats.suspicious,
        total: s.total,
      }))
  })

  const urlscanSummary = computed(() => {
    const scans = analysisResult.value?.threat_intel.urlscan ?? []
    if (!scans.length) {
      return { completed: 0, malicious: 0, suspicious: 0, benign: 0, unknown: 0, total: 0 }
    }
    const counts = { malicious: 0, suspicious: 0, benign: 0, unknown: 0 }
    let completed = 0
    for (const scan of scans) {
      if (urlscanVerdict(scan) === 'Completed') completed += 1
      // Check URLscan verdict first, then Sublime ML label
      const urlscanRisk = (scan.verdict || '').toLowerCase()
      const sublimeMlLabel = (scan.ml_link?.label || '').toLowerCase()
      // "phishing" from Sublime ML counts as malicious
      if (urlscanRisk === 'malicious' || sublimeMlLabel === 'malicious' || sublimeMlLabel === 'phishing') {
        counts.malicious += 1
      } else if (urlscanRisk === 'suspicious' || sublimeMlLabel === 'suspicious') {
        counts.suspicious += 1
      } else if (urlscanRisk === 'benign' || sublimeMlLabel === 'benign') {
        counts.benign += 1
      } else {
        counts.unknown += 1
      }
    }
    return {
      completed,
      ...counts,
      total: scans.length,
    }
  })

  const mergeUrlscanSubmission = (previous: UrlscanSubmission, incoming: UrlscanSubmission): UrlscanSubmission => {
    return {
      ...previous,
      ...incoming,
      url: incoming.url || previous.url,
      result_url: incoming.result_url || previous.result_url,
      screenshot_url: incoming.screenshot_url || previous.screenshot_url,
      verdict: incoming.verdict || previous.verdict,
      visibility: incoming.visibility || previous.visibility,
      ml_link: incoming.ml_link || previous.ml_link,
    }
  }

  const refreshUrlscanSubmission = async (scanId: string) => {
    if (!scanId || !analysisResult.value) return
    refreshingScans.value[scanId] = true
    refreshErrors.value[scanId] = null

    // Get store directly to update state properly (analysisResult is a computed, not directly assignable)
    const store = useAnalysisStore()

    try {

      const resp = await fetch(`${API_BASE_URL}/api/v1/analysis/urlscan/${encodeURIComponent(scanId)}`)
      if (!resp.ok) {
        const detail = await resp.text()
        throw new Error(`Refresh failed: ${resp.status} ${detail}`)
      }
      const updated = (await resp.json()) as UrlscanSubmission

      const current = analysisResult.value
      const submissions = current.threat_intel.urlscan ?? []
      const idx = submissions.findIndex((scan) => scan.scan_id === scanId)
      if (idx !== -1) {
        const nextSubmissions = [...submissions]
        const existingSubmission = nextSubmissions[idx]
        if (!existingSubmission) {
          nextSubmissions[idx] = updated
        } else {
          nextSubmissions[idx] = mergeUrlscanSubmission(existingSubmission, updated)
        }
        // Update via store instead of directly assigning to computed
        const updatedResult = {
          ...current,
          threat_intel: { ...current.threat_intel, urlscan: nextSubmissions },
        }
        store.setAnalysisResult(updatedResult)

      }
    } catch (error) {
      console.error('URLscan refresh error:', error)
      refreshErrors.value[scanId] = error instanceof Error ? error.message : 'Unable to refresh submission.'
    } finally {
      refreshingScans.value[scanId] = false
    }
  }

  // Refresh VirusTotal data for a specific URL
  const refreshingVtUrls = ref<Record<string, boolean>>({})
  const vtRefreshErrors = ref<Record<string, string | null>>({})

  const refreshVirusTotalUrl = async (url: string) => {
    if (!url || !analysisResult.value) return
    refreshingVtUrls.value[url] = true
    vtRefreshErrors.value[url] = null

    const store = useAnalysisStore()

    try {
      const resp = await fetch(`${API_BASE_URL}/api/v1/analysis/virustotal/url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      })
      if (!resp.ok) {
        const detail = await resp.text()
        throw new Error(`VT refresh failed: ${resp.status} ${detail}`)
      }
      const updated = await resp.json()

      // Only add if we got actual data (not an error)
      if (updated.data && !updated.error) {
        const current = analysisResult.value
        const vtLookups = current.threat_intel.virustotal ?? []

        // Check if we already have this URL result
        const existingIdx = vtLookups.findIndex(
          (l: VirusTotalLookup) => l.indicator_type === 'url' && l.indicator === url
        )

        const newLookup: VirusTotalLookup = {
          indicator: updated.indicator,
          indicator_type: updated.indicator_type,
          data: updated.data,
          error: updated.error,
        }

        let nextVtLookups: VirusTotalLookup[]
        if (existingIdx !== -1) {
          nextVtLookups = [...vtLookups]
          nextVtLookups[existingIdx] = newLookup
        } else {
          nextVtLookups = [...vtLookups, newLookup]
        }

        const updatedResult = {
          ...current,
          threat_intel: { ...current.threat_intel, virustotal: nextVtLookups },
        }
        store.setAnalysisResult(updatedResult)
      }
    } catch (error) {
      console.error('VT URL refresh error:', error)
      vtRefreshErrors.value[url] = error instanceof Error ? error.message : 'Unable to refresh VT data.'
    } finally {
      refreshingVtUrls.value[url] = false
    }
  }

  // Auto-refresh pending URLscan submissions in background
  const autoRefreshInterval = ref<number | null>(null)
  const autoRefreshStartTime = ref<number | null>(null)
  const AUTO_REFRESH_INTERVAL_MS = 12000 // Poll every 12 seconds
  const AUTO_REFRESH_MAX_DURATION_MS = 120000 // Stop after 2 minutes

  const startAutoRefresh = () => {
    if (autoRefreshInterval.value) return // Already running

    autoRefreshStartTime.value = Date.now()


    autoRefreshInterval.value = window.setInterval(async () => {
      // Check if we should stop
      const elapsed = Date.now() - (autoRefreshStartTime.value ?? 0)
      if (elapsed > AUTO_REFRESH_MAX_DURATION_MS) {

        stopAutoRefresh()
        return
      }

      // Find pending scans using consistent verdict checking
      const scans = analysisResult.value?.threat_intel.urlscan ?? []
      const pendingScans = scans.filter(scan => {
        if (!scan.scan_id) return false
        if (refreshingScans.value[scan.scan_id]) return false // Already refreshing
        const verdict = urlscanVerdict(scan)
        // Use consistent pending detection
        return verdict === 'Pending' || isVerdictPending(scan.verdict)
      })

      if (pendingScans.length === 0) {

        stopAutoRefresh()
        return
      }

      // Refresh up to 3 pending scans in parallel
      const toRefresh = pendingScans.slice(0, 3)

      await Promise.all(toRefresh.map(scan => refreshUrlscanSubmission(scan.scan_id!)))
    }, AUTO_REFRESH_INTERVAL_MS)
  }

  const stopAutoRefresh = () => {
    if (autoRefreshInterval.value) {
      window.clearInterval(autoRefreshInterval.value)
      autoRefreshInterval.value = null
      autoRefreshStartTime.value = null

    }
  }

  // Watch for new analysis results and start auto-refresh if there are pending scans
  watch(
    () => analysisResult.value?.threat_intel.urlscan,
    (scans) => {
      if (!scans || scans.length === 0) {
        stopAutoRefresh()
        return
      }

      // Check if any scans are pending using consistent logic
      const hasPending = scans.some(scan => {
        if (!scan.scan_id) return false
        const verdict = urlscanVerdict(scan)
        return verdict === 'Pending' || isVerdictPending(scan.verdict)
      })

      if (hasPending && !autoRefreshInterval.value) {
        startAutoRefresh()
      } else if (!hasPending) {
        stopAutoRefresh()
      }
    },
    { immediate: true }
  )

  // Auto-refresh VT data for URLs showing "No data"
  const vtAutoRefreshDone = ref<Set<string>>(new Set())

  watch(
    [() => analysisResult.value?.threat_intel.urlscan, () => analysisResult.value?.threat_intel.virustotal],
    async ([scans, vtResults]) => {
      if (!scans || scans.length === 0) return

      // Find URLs that don't have VT data yet
      const vtIndicators = new Set(
        (vtResults ?? []).map(vt =>
          vt.indicator_type === 'url' ? vt.indicator : null
        ).filter(Boolean)
      )

      // Also check domain matches
      const vtDomains = new Set(
        (vtResults ?? []).map(vt =>
          vt.indicator_type === 'domain' ? vt.indicator.toLowerCase() : null
        ).filter(Boolean)
      )

      const urlsNeedingRefresh: string[] = []
      for (const scan of scans) {
        if (!scan.url || vtAutoRefreshDone.value.has(scan.url)) continue

        // Check if we have VT data for this URL (exact match or domain)
        const hasUrlResult = vtIndicators.has(scan.url)
        let hasDomainResult = false
        try {
          const domain = new URL(scan.url).hostname.replace(/^www\./, '').toLowerCase()
          hasDomainResult = vtDomains.has(domain)
        } catch { }

        if (!hasUrlResult && !hasDomainResult) {
          urlsNeedingRefresh.push(scan.url)
        }
      }

      // Limit concurrent refreshes to avoid overwhelming the API
      const urlsToRefresh = urlsNeedingRefresh.slice(0, 3)
      for (const url of urlsToRefresh) {
        vtAutoRefreshDone.value.add(url) // Mark as attempted
        refreshVirusTotalUrl(url) // Fire and forget
      }
    },
    { immediate: true }
  )

  // Cleanup on unmount
  onUnmounted(() => {
    stopAutoRefresh()
  })

  return {
    copiedTargets,
    copiedHashes,
    copyHash,
    copyTarget,
    formatUrl,
    getVtFilter,
    getVtResultForFile,
    isVirusTotalExpanded,
    openVtForFile,
    setVtFilter,
    setVtSort,
    sortGlyph,
    toggleVirusTotalEngines,
    urlscanImageLoaded,
    urlscanKey,
    urlscanVerdict,
    urlscanSubmissions,
    urlscanCompletedSubmissions,
    vtCategories: VT_CATEGORIES,
    vtFilteredSummaries,
    vtGlobalFilter,
    vtIndicatorBuckets,
    vtViewEngines,
    vtSummaryCard,
    vtSummary: vtSummaryCard,
    vtByType,
    vtFlaggedItems,
    urlscanSummary,
    refreshUrlscanSubmission,
    refreshingScans,
    refreshErrors,
    virusTotalSummaries,
    ipqsResults,
    hybridAnalysisResults,
    // VT URL refresh
    refreshVirusTotalUrl,
    refreshingVtUrls,
    vtRefreshErrors,
  }
}
const urlscanKey = (scan: UrlscanSubmission, index: number) => scan.scan_id ?? scan.url ?? `idx-${index}`
