export type UrlscanMlLink = {
  label?: string | null
  score?: number | string | null
  effective_url?: string | null
  contains_login?: boolean | null
  contains_captcha?: boolean | null
  redirect_count?: number | null
  redirects?: string[] | null
  screenshot?: string | null
  page_status?: number | null
}

export type UrlscanSubmission = {
  url?: string | null
  scan_id?: string | null
  result_url?: string | null
  screenshot_url?: string | null
  visibility?: string | null
  verdict?: string | null
  error?: string | null
  ml_link?: UrlscanMlLink | null
}

// VirusTotal API data structure
export type VTDataAttributes = {
  last_analysis_stats?: {
    malicious?: number
    suspicious?: number
    harmless?: number
    undetected?: number
  }
  last_analysis_results?: Record<string, { category: string; result: string | null }>
  [key: string]: unknown
}

export type VTData = {
  id?: string
  type?: string
  attributes?: VTDataAttributes
}

export type VirusTotalLookup = {
  indicator: string
  indicator_type: string
  error?: string | null
  data?: VTData | null
  sources?: string[]
}

export type IPQSLookup = {
  ip: string
  source?: string | null
  fraud_score?: number | null
  country_code?: string | null
  city?: string | null
  isp?: string | null
  is_vpn?: boolean | null
  is_tor?: boolean | null
  is_proxy?: boolean | null
  is_bot?: boolean | null
  is_crawler?: boolean | null
  recent_abuse?: boolean | null
  host?: string | null
  error?: string | null
}

export type HybridAnalysisLookup = {
  sha256: string
  verdict?: string | null
  threat_score?: number | null
  threat_level?: number | null
  av_detect?: number | null
  vx_family?: string | null
  tags?: string[] | null
  file_type?: string | null
  environment_description?: string | null
  report_url?: string | null
  error?: string | null
  // Enhanced fields
  submit_name?: string | null
  analysis_start_time?: string | null
  size?: number | null
  total_processes?: number | null
  total_signatures?: number | null
  total_network_connections?: number | null
  domains?: string[] | null
  hosts?: string[] | null
  classification_tags?: string[] | null
  mitre_attcks?: string[] | null
  is_interesting?: boolean | null
}

export type ThreatIntelReport = {
  virustotal: VirusTotalLookup[]
  urlscan: UrlscanSubmission[]
  ipqs: IPQSLookup[]
  hybrid_analysis: HybridAnalysisLookup[]
  notes?: string | null
}

export type EmailAttachment = {
  filename?: string | null
  content_type: string
  size: number
  sha256: string
  content_id?: string | null
}

export type EmailAddress = {
  name?: string | null
  address?: string | null
  domain?: string | null
}

export type ParsedEmail = {
  from?: EmailAddress | null
  subject?: string | null
  sender_domain?: string | null
  attachments?: EmailAttachment[]
  [key: string]: unknown
}

export type SublimeSummary = {
  mdm?: Record<string, unknown> | null
  analysis?: { rule_results?: unknown[] } | null
  attack_score?: {
    score?: unknown
    graymail_score?: unknown
    verdict?: unknown
    top_signals?: Array<{ category?: unknown; description?: unknown }>
  } | null
  rule_hits: Array<Record<string, unknown>>
  insight_hits: Array<Record<string, unknown>>
  errors: Record<string, string>
}

export type CombinedAnalysisResult = {
  parsed_email: ParsedEmail
  sublime: SublimeSummary
  threat_intel: ThreatIntelReport
  raw_eml?: string | null
}

export type VirusTotalEngine = {
  engine: string
  category: string
  result: string
}

export type VirusTotalStats = {
  harmless: number
  malicious: number
  suspicious: number
  undetected: number
  timeout: number
}

export type VTSummary = {
  indicator: string
  indicator_type: string
  id?: string
  stats: VirusTotalStats
  total: number
  engines: VirusTotalEngine[]
  error: string | null
  verdict: string
  verdictClass: string
  sources: string[]
}

// Link Analysis Result from /api/analysis/link endpoint
export type LinkAnalysisResult = {
  urlscan?: UrlscanSubmission | null
  virustotal?: VirusTotalLookup[] | null
  is_download?: boolean
  content_type?: string | null
  // Risk assessment (calculated by backend)
  risk_score?: number
  overall_verdict?: string
  risk_factors?: string[]
}

// File Analysis Result from /api/analysis/file endpoint
export type FileAnalysisResult = {
  filename?: string | null
  sha256?: string | null
  md5?: string | null
  size?: number | null
  file_type?: string | null
  virustotal?: VirusTotalLookup | null
  hybrid_analysis?: HybridAnalysisLookup | null
  verdict?: string | null
  risk_score?: number | null
  risk_level?: 'low' | 'medium' | 'high' | 'critical' | null
}
