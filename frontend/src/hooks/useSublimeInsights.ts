import { computed, ref } from 'vue'
import type { Ref } from 'vue'

import type { CombinedAnalysisResult } from '@/types/analysis'

export function useSublimeInsights(analysisResult: Ref<CombinedAnalysisResult | null>) {
  const showAllRules = ref(false)
  const showAllInsights = ref(false)
  const insightSeverityFilter = ref<'ALL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'>('ALL')

  const attackScoreSummary = computed(() => {
    const raw = analysisResult.value?.sublime.attack_score
    if (!raw) return null

    const score = Number(raw.score ?? NaN)
    const graymail = Number(raw.graymail_score ?? NaN)
    const verdict = typeof raw.verdict === 'string' ? raw.verdict : null
    const topSignals = Array.isArray(raw.top_signals)
      ? raw.top_signals
        .map((signal) => {
          const obj = signal as { category?: unknown; description?: unknown }
          return {
            category: typeof obj.category === 'string' ? obj.category : 'Signal',
            description: typeof obj.description === 'string' ? obj.description : '',
          }
        })
        .filter((signal) => signal.description)
        .slice(0, 5)
      : []

    return {
      score: Number.isFinite(score) ? score : null,
      graymailScore: Number.isFinite(graymail) ? graymail : null,
      verdict,
      topSignals,
    }
  })

  const ruleSummary = computed(() => {
    const sublime = analysisResult.value?.sublime
    if (!sublime) {
      return { matched: 0, insights: 0, totalRules: null as number | null }
    }
    const ruleResults = Array.isArray(sublime.analysis?.rule_results) ? sublime.analysis?.rule_results : null
    return {
      matched: sublime.rule_hits.length,
      insights: sublime.insight_hits.length,
      totalRules: ruleResults ? ruleResults.length : null,
    }
  })

  const uiRuleHits = computed(() => {
    const hits = (analysisResult.value?.sublime.rule_hits ?? []) as Array<Record<string, unknown>>
    const pick = (obj: any, ...paths: string[]) => {
      for (const path of paths) {
        const value = path
          .split('.')
          .reduce((acc: any, key: string) => (acc && typeof acc === 'object' ? acc[key] : undefined), obj)
        if (typeof value === 'string' && value.trim() !== '') return value
      }
      return ''
    }

    const severityClass = (level: string) => {
      switch (level) {
        case 'CRITICAL':
        case 'HIGH':
          return 'sev--high'
        case 'MEDIUM':
          return 'sev--medium'
        case 'LOW':
          return 'sev--low'
        default:
          return 'sev--info'
      }
    }

    const normalizeSeverity = (raw: unknown) => {
      const value = typeof raw === 'string' ? raw.toUpperCase() : ''
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(value)) return value
      if (value.trim() === 'INFORMATIONAL') return 'INFO'
      return 'INFO'
    }

    // Severity order for sorting: CRITICAL/HIGH first, then MEDIUM, LOW, INFO
    const severityOrder: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
      INFO: 4,
    }

    return hits
      .map((hit, index) => {
        const title = pick(hit, 'rule.name', 'rule.display_name', 'title', 'name', 'rule_id') || 'Matched rule'
        const id = pick(hit, 'id', 'rule.id', 'uuid', 'rule.uuid') || String(index + 1)
        const severity = normalizeSeverity(pick(hit, 'rule.severity', 'severity', 'level', 'priority'))
        return { title, id, severity, sevClass: severityClass(severity), raw: hit }
      })
      .sort((a, b) => (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99))
  })

  const displayedUiRuleHits = computed(() => uiRuleHits.value)

  const uiInsightHits = computed(() => {
    const hits = (analysisResult.value?.sublime.insight_hits ?? []) as Array<Record<string, unknown>>

    const normalizeSeverity = (raw: unknown) => {
      const value = typeof raw === 'string' ? raw.toUpperCase() : ''
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'INFORMATIONAL'].includes(value)) {
        return value === 'INFORMATIONAL' ? 'INFO' : value
      }
      return 'INFO'
    }

    const summarize = (val: unknown): { text: string; extraCount: number } => {
      if (typeof val === 'boolean') return { text: val ? 'Condition matched' : 'No match', extraCount: 0 }
      if (typeof val === 'number') return { text: String(val), extraCount: 0 }
      if (typeof val === 'string') {
        return { text: val.length > 160 ? `${val.slice(0, 157)}...` : val, extraCount: 0 }
      }
      if (Array.isArray(val)) {
        const strings = val.filter((item) => typeof item === 'string') as string[]
        if (strings.length) {
          const head = strings.slice(0, 5)
          const extra = Math.max(0, strings.length - head.length)
          return { text: head.join(', '), extraCount: extra }
        }
        return { text: `List of ${val.length} items`, extraCount: 0 }
      }
      if (val && typeof val === 'object') {
        const keys = Object.keys(val as Record<string, unknown>)
        const head = keys.slice(0, 5)
        const extra = Math.max(0, keys.length - head.length)
        return { text: head.length ? `Fields: ${head.join(', ')}` : 'Object result', extraCount: extra }
      }
      return { text: '', extraCount: 0 }
    }

    return hits.map((hit, index) => {
      const query = (hit['query'] ?? {}) as Record<string, unknown>
      const title = (typeof query['name'] === 'string' && query['name']) || (typeof hit['name'] === 'string' && hit['name']) || `Insight ${index + 1}`
      const severity = normalizeSeverity(query['severity'])
      const { text, extraCount } = summarize(hit['result'])

      const sevClass =
        severity === 'CRITICAL' || severity === 'HIGH'
          ? 'sev--high'
          : severity === 'MEDIUM'
            ? 'sev--medium'
            : severity === 'LOW'
              ? 'sev--low'
              : 'sev--info'

      return { title, severity, sevClass, desc: text, extraCount, raw: hit }
    })
  })

  type InsightBucket = 'ALL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  type InsightBuckets = Record<InsightBucket, number>

  const insightCounts = computed<InsightBuckets>(() => {
    const counts: InsightBuckets = { ALL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    for (const insight of uiInsightHits.value) {
      counts.ALL += 1
      const bucket = (insight.severity === 'INFORMATIONAL' ? 'INFO' : insight.severity) as InsightBucket
      counts[bucket] = (counts[bucket] ?? 0) + 1
    }
    return counts
  })

  const filteredUiInsightHits = computed(() => {
    if (insightSeverityFilter.value === 'ALL') return uiInsightHits.value
    return uiInsightHits.value.filter((insight) => insight.severity === insightSeverityFilter.value)
  })

  const displayedUiInsightHits = computed(() => filteredUiInsightHits.value)

  return {
    attackScoreSummary,
    displayedUiInsightHits,
    displayedUiRuleHits,
    filteredUiInsightHits,
    insightCounts,
    insightSeverityFilter,
    ruleSummary,
    showAllInsights,
    showAllRules,
  }
}
