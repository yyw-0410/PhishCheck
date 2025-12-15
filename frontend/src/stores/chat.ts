import { ref, computed } from 'vue'
import { defineStore } from 'pinia'
import { useAnalysisStore } from './analysis'
import { API_BASE_URL } from '@/services/api'

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
  sources?: Array<{ title: string; id: string }>
}

export type ChatMode = 'general' | 'analysis'

export interface ChatState {
  messages: ChatMessage[]
  isLoading: boolean
  error: string | null
  suggestedQuestions: string[]
  analysisQuestions: string[]
  chatMode: ChatMode
}

export const useChatStore = defineStore('chat', () => {
  const messages = ref<ChatMessage[]>([])
  const isLoading = ref(false)
  const isTyping = ref(false) // Track when AI is typing for auto-scroll
  const error = ref<string | null>(null)
  const suggestedQuestions = ref<string[]>([])
  const analysisQuestions = ref<string[]>([])
  const chatMode = ref<ChatMode>('general')

  // Rate limiting: max 10 messages per minute
  const RATE_LIMIT_MAX = 10
  const RATE_LIMIT_WINDOW_MS = 60000 // 1 minute
  const messageTimes = ref<number[]>([])
  const isRateLimited = computed(() => {
    const now = Date.now()
    const recentMessages = messageTimes.value.filter(t => now - t < RATE_LIMIT_WINDOW_MS)
    return recentMessages.length >= RATE_LIMIT_MAX
  })

  // Question quota: max 10 questions per chat session
  const QUESTION_QUOTA = 10
  const questionCount = ref(0)
  const isQuotaExceeded = computed(() => questionCount.value >= QUESTION_QUOTA)
  const remainingQuestions = computed(() => Math.max(0, QUESTION_QUOTA - questionCount.value))
  const rateLimitRemainingTime = computed(() => {
    if (!isRateLimited.value) return 0
    const now = Date.now()
    const oldestInWindow = messageTimes.value.find(t => now - t < RATE_LIMIT_WINDOW_MS)
    if (!oldestInWindow) return 0
    return Math.ceil((RATE_LIMIT_WINDOW_MS - (now - oldestInWindow)) / 1000)
  })

  const hasMessages = computed(() => messages.value.length > 0)

  // Get current questions based on mode
  const currentQuestions = computed(() => {
    return chatMode.value === 'analysis' ? analysisQuestions.value : suggestedQuestions.value
  })

  const generateId = () => {
    return `msg_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`
  }

  // Clear chat and start fresh conversation
  const clearChat = () => {
    messages.value = []
    error.value = null
    isTyping.value = false
    questionCount.value = 0 // Reset question quota
    // Don't clear rate limit times - they persist across conversations
  }

  const addMessage = (role: 'user' | 'assistant', content: string, sources?: Array<{ title: string; id: string }>) => {
    const message: ChatMessage = {
      id: generateId(),
      role,
      content,
      timestamp: new Date(),
      sources
    }
    messages.value.push(message)
    return message
  }

  // Build analysis context from the analysis store
  const buildAnalysisContext = () => {
    const analysisStore = useAnalysisStore()

    // Check for email analysis first
    if (analysisStore.analysisResult) {
      return buildEmailContext(analysisStore.analysisResult)
    }

    // Check for link analysis
    if (analysisStore.linkAnalysisResult) {
      return buildLinkContext(analysisStore.linkAnalysisResult)
    }

    // Check for file analysis
    if (analysisStore.fileAnalysisResult) {
      return buildFileContext(analysisStore.fileAnalysisResult)
    }

    return null
  }

  // Build context for email analysis
  const buildEmailContext = (result: any) => {
    const context: Record<string, any> = { analysisType: 'email' }

    // Email metadata
    const parsed = result.parsed_email
    if (parsed) {
      context.emailMetadata = {
        subject: parsed.subject || 'N/A',
        from: typeof parsed.from === 'object' ? `${(parsed.from as any).name || ''} <${(parsed.from as any).address || ''}>` : parsed.from,
        to: Array.isArray(parsed.to) ? parsed.to.map((t: any) => typeof t === 'object' ? t.address : t).join(', ') : parsed.to,
        date: parsed.date || 'N/A'
      }

      // Email body (truncated to 1000 chars to avoid context overflow)
      if (parsed.body) {
        const bodyText = parsed.body.text || parsed.body.html?.replace(/<[^>]*>/g, '') || ''
        if (bodyText) {
          context.emailBody = bodyText.slice(0, 1000) + (bodyText.length > 1000 ? '...[truncated]' : '')
        }
      }

      // Important headers (limited)
      if (parsed.headers?.length) {
        const importantHeaders = ['Return-Path', 'Received', 'X-Originating-IP', 'X-Mailer', 'Reply-To']
        context.headers = parsed.headers
          .filter((h: any) => importantHeaders.some(ih => h.name?.toLowerCase().includes(ih.toLowerCase())))
          .slice(0, 5)
          .map((h: any) => ({ name: h.name, value: (h.value || '').slice(0, 200) }))
      }

      // Attachments info
      if (parsed.attachments?.length) {
        context.attachments = parsed.attachments.slice(0, 10).map((att: any) => ({
          filename: att.filename || att.name || 'Unknown',
          contentType: att.content_type || att.contentType || 'Unknown',
          size: att.size || 0
        }))
      }

      // Links from body (first 10)
      if (parsed.links?.length) {
        context.bodyLinks = parsed.links.slice(0, 10).map((link: any) => ({
          text: (link.text || '').slice(0, 100),
          href: link.href || link.url || ''
        }))
      }
    }

    // Authentication results
    if (parsed?.authentication) {
      context.authentication = {
        spf: parsed.authentication.spf || 'N/A',
        dkim: parsed.authentication.dkim || 'N/A',
        dmarc: parsed.authentication.dmarc || 'N/A'
      }
    }

    // Sublime rules triggered
    if (result.sublime?.rule_hits?.length) {
      // Limit to 10 rules to prevent context from being too large
      context.sublimeRules = result.sublime.rule_hits.slice(0, 10).map((rule: any) => ({
        name: rule.name || 'Unknown',
        severity: rule.severity || 'N/A',
        description: (rule.description || 'No description').slice(0, 200)
      }))
    }

    // Threat indicators from insights (limited)
    if (result.sublime?.insight_hits?.length) {
      context.threatIndicators = result.sublime.insight_hits.slice(0, 10).map((insight: any) => ({
        type: insight.name || 'Insight',
        value: (insight.description || 'N/A').slice(0, 200),
        severity: insight.severity || 'info'
      }))
    }

    // URLs found - send first 5 for testing (extract domain only for safety)
    if (parsed?.urls?.length) {
      context.urlCount = parsed.urls.length
      // Extract domains only (safer than full URLs)
      const domains = parsed.urls.slice(0, 5).map((url: string) => {
        try {
          return new URL(url.startsWith('http') ? url : `https://${url}`).hostname
        } catch {
          return url.split('/')[0]
        }
      })
      context.domains = [...new Set(domains)] // unique domains
    }

    // IP addresses - use IPs from IPQS results (these are the ones displayed in the IP Reputation UI)
    if (result.threat_intel?.ipqs?.length) {
      const ipqsData = result.threat_intel.ipqs
      const checkedIps = ipqsData.map((i: any) => i.ip || i.indicator).filter(Boolean)
      context.ipCount = checkedIps.length
      context.ipAddresses = checkedIps.slice(0, 5)

      // IPQS summary stats
      context.ipqsSummary = {
        total: ipqsData.length,
        highRisk: ipqsData.filter((i: any) => (i.data?.fraud_score ?? 0) > 75).length,
        vpnCount: ipqsData.filter((i: any) => i.data?.vpn).length,
        proxyCount: ipqsData.filter((i: any) => i.data?.proxy).length
      }
    } else if (parsed?.ip_addresses?.length) {
      // Fallback to parsed IPs if no IPQS data
      context.ipCount = parsed.ip_addresses.length
      context.ipAddresses = parsed.ip_addresses.slice(0, 5)
    }

    // Attack score and verdict
    if (result.sublime?.attack_score) {
      context.attackScore = result.sublime.attack_score.score
      context.verdict = result.sublime.attack_score.verdict
    }

    // VirusTotal results - send indicators that have detections
    if (result.threat_intel?.virustotal?.length) {
      const vtData = result.threat_intel.virustotal
      let totalMalicious = 0
      let totalSuspicious = 0
      const flaggedIndicators: Array<{ indicator: string, malicious: number, suspicious: number }> = []

      vtData.forEach((vt: any) => {
        const mal = vt.data?.attributes?.last_analysis_stats?.malicious || 0
        const sus = vt.data?.attributes?.last_analysis_stats?.suspicious || 0
        totalMalicious += mal
        totalSuspicious += sus

        // Include indicators that have detections (limit to 10)
        if ((mal > 0 || sus > 0) && flaggedIndicators.length < 10) {
          flaggedIndicators.push({
            indicator: vt.indicator || 'Unknown',
            malicious: mal,
            suspicious: sus
          })
        }
      })

      context.virustotalSummary = {
        total: vtData.length,
        maliciousDetections: totalMalicious,
        suspiciousDetections: totalSuspicious,
        flaggedIndicators: flaggedIndicators
      }
    }

    return context
  }

  // Build context for link analysis
  const buildLinkContext = (result: any) => {
    const context: Record<string, any> = { analysisType: 'link' }

    // URL info
    context.url = result.urlscan?.url || result.url

    // VirusTotal stats
    if (result.virustotal?.[0]?.data?.attributes?.last_analysis_stats) {
      const stats = result.virustotal[0].data.attributes.last_analysis_stats
      context.virustotal = {
        malicious: stats.malicious || 0,
        suspicious: stats.suspicious || 0,
        harmless: stats.harmless || 0
      }
    }

    // URLscan verdict
    if (result.urlscan) {
      context.urlscan = {
        verdict: result.urlscan.verdict,
        tags: result.urlscan.tags || []
      }
    }

    // Sublime ML analysis
    if (result.urlscan?.ml_link) {
      context.sublimeMl = {
        label: result.urlscan.ml_link.label,
        score: result.urlscan.ml_link.score,
        containsLogin: result.urlscan.ml_link.contains_login,
        containsCaptcha: result.urlscan.ml_link.contains_captcha,
        redirectCount: result.urlscan.ml_link.redirect_count
      }
    }

    return context
  }

  // Build context for file analysis - Enhanced with more Hybrid Analysis fields
  const buildFileContext = (result: any) => {
    const context: Record<string, any> = { analysisType: 'file' }

    // Overall verdict and score
    context.verdict = result.overall_verdict
    context.riskScore = result.risk_score

    // File info
    if (result.file_info || result.virustotal) {
      context.fileInfo = {
        filename: result.file_info?.filename || result.virustotal?.meaningful_name,
        size: result.file_info?.size || result.virustotal?.size,
        sha256: result.file_info?.sha256 || result.virustotal?.sha256,
        contentType: result.file_info?.content_type || result.virustotal?.type_description
      }
    }

    // VirusTotal stats
    if (result.virustotal?.stats) {
      context.virustotal = {
        malicious: result.virustotal.stats.malicious || 0,
        suspicious: result.virustotal.stats.suspicious || 0,
        harmless: result.virustotal.stats.harmless || 0,
        total: (result.virustotal.stats.malicious || 0) +
          (result.virustotal.stats.suspicious || 0) +
          (result.virustotal.stats.harmless || 0) +
          (result.virustotal.stats.undetected || 0)
      }
    }

    // Hybrid Analysis - Enhanced with more fields
    if (result.hybrid_analysis) {
      const ha = result.hybrid_analysis
      context.hybridAnalysis = {
        verdict: ha.verdict,
        threatScore: ha.threat_score,
        avDetections: ha.av_detect,
        malwareFamily: ha.vx_family,
        fileType: ha.file_type,
        environment: ha.environment_description,
        analysisTime: ha.analysis_start_time,
        // Behavioral data
        totalProcesses: ha.total_processes,
        totalSignatures: ha.total_signatures,
        totalNetworkConnections: ha.total_network_connections,
        // Tags and classification
        tags: ha.tags?.slice(0, 10),
        classificationTags: ha.classification_tags?.slice(0, 5),
        // Network indicators (limit to prevent context bloat)
        domainsContacted: ha.domains?.slice(0, 10),
        hostsContacted: ha.hosts?.slice(0, 10),
        // MITRE ATT&CK
        mitreAttacks: ha.mitre_attcks?.slice(0, 10),
        // Report link for reference
        reportUrl: ha.report_url
      }
    }

    return context
  }

  const sendMessage = async (query: string) => {
    if (!query.trim() || query.length > 5000) return

    // Check question quota
    if (isQuotaExceeded.value) {
      error.value = 'You have reached the 10-question limit for this chat. Please start a new chat to continue.'
      return
    }

    // Check rate limit
    if (isRateLimited.value) {
      error.value = `Rate limit reached. Please wait ${rateLimitRemainingTime.value} seconds.`
      return
    }

    // Record this message time for rate limiting
    messageTimes.value.push(Date.now())
    // Clean up old times
    const now = Date.now()
    messageTimes.value = messageTimes.value.filter(t => now - t < RATE_LIMIT_WINDOW_MS)

    // Add user message
    addMessage('user', query)

    isLoading.value = true
    error.value = null

    try {
      // Build analysis context from current analysis
      const analysis_context = buildAnalysisContext()

      // Build conversation history (last 10 messages for context)
      const conversation_history = messages.value.slice(-10).map(m => ({
        role: m.role,
        content: m.content
      }))

      const response = await fetch(`${API_BASE_URL}/api/v1/ai`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          query,
          analysis_context,
          conversation_history
        })
      })

      if (!response.ok) {
        throw new Error(`Error: ${response.status} ${response.statusText}`)
      }

      const data = await response.json()

      // Increment question count on successful response
      questionCount.value++

      // Add assistant response with typing animation
      const messageId = generateId()
      const message: ChatMessage = {
        id: messageId,
        role: 'assistant',
        content: '',
        timestamp: new Date(),
        sources: data.sources
      }
      messages.value.push(message)

      // Find the message index for reactive updates
      const messageIndex = messages.value.length - 1

      // Animate the response typing
      const fullText = data.answer
      const charsPerTick = 5 // Characters to add per tick for smooth but fast typing
      const tickInterval = 15 // Milliseconds between ticks

      let charIndex = 0
      isTyping.value = true // Start typing animation
      const typeInterval = setInterval(() => {
        if (charIndex < fullText.length) {
          // Add multiple characters per tick for faster typing
          const endIndex = Math.min(charIndex + charsPerTick, fullText.length)
          // Update content directly on the message in the array
          const msg = messages.value[messageIndex]
          if (msg) {
            msg.content = fullText.substring(0, endIndex)
            // Force reactivity by triggering array update
            messages.value = [...messages.value]
          }
          charIndex = endIndex
        } else {
          clearInterval(typeInterval)
          isTyping.value = false // Typing complete
        }
      }, tickInterval)
    } catch (err) {
      error.value = err instanceof Error ? err.message : 'Failed to get response'
      // Add error message to chat
      addMessage('assistant', 'Sorry, I encountered an error while processing your question. Please try again.')
      isTyping.value = false
    } finally {
      isLoading.value = false
    }
  }

  const fetchSuggestedQuestions = async () => {
    try {
      // Fetch both general and analysis questions
      const [generalRes, analysisRes] = await Promise.all([
        fetch(`${API_BASE_URL}/api/v1/ai/suggestions`),
        fetch(`${API_BASE_URL}/api/v1/ai/analysis-questions`)
      ])

      if (generalRes.ok) {
        const data = await generalRes.json()
        suggestedQuestions.value = data.questions
      }

      if (analysisRes.ok) {
        const data = await analysisRes.json()
        analysisQuestions.value = data.questions
      }
    } catch (err) {
      console.error('Failed to fetch suggested questions:', err)
      // Use fallback suggestions
      suggestedQuestions.value = [
        'What is phishing?',
        'How can I identify a phishing email?',
        'What are SPF, DKIM, and DMARC?',
        'What should I do if I clicked a phishing link?'
      ]
      analysisQuestions.value = [
        'Is this email safe?',
        'What threats were detected?',
        'Explain the authentication results',
        'What should I do about this email?'
      ]
    }
  }

  const setChatMode = (mode: ChatMode) => {
    chatMode.value = mode
  }

  const startNewChat = () => {
    messages.value = []
    error.value = null
    chatMode.value = 'general'
    questionCount.value = 0 // Reset quota
  }

  const startAnalysisChat = () => {
    messages.value = []
    error.value = null
    chatMode.value = 'analysis'
    questionCount.value = 0 // Reset quota
  }

  return {
    messages,
    isLoading,
    isTyping,
    isRateLimited,
    rateLimitRemainingTime,
    isQuotaExceeded,
    remainingQuestions,
    questionCount,
    error,
    suggestedQuestions,
    analysisQuestions,
    chatMode,
    hasMessages,
    currentQuestions,
    addMessage,
    sendMessage,
    fetchSuggestedQuestions,
    setChatMode,
    startNewChat,
    startAnalysisChat,
    clearChat
  }
})
