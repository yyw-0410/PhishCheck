import { computed } from 'vue'
import type { Ref } from 'vue'

import type { CombinedAnalysisResult, EmailAttachment } from '@/types/analysis'

const formatBytes = (bytes: number) => {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const value = bytes / Math.pow(1024, i)
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[i]}`
}

export function useParsedEmail(analysisResult: Ref<CombinedAnalysisResult | null>) {
  const attachmentSummary = computed(() => {
    const attachments = (analysisResult.value?.parsed_email?.attachments ?? []) as EmailAttachment[]
    if (!attachments.length) return null
    const samples = attachments.map((attachment) => {
      // Extract file extension
      const filename = attachment.filename || 'Unnamed attachment'
      const ext = filename.includes('.') ? filename.split('.').pop()?.toLowerCase() : null

      // Determine file category based on MIME type
      const mimeType = attachment.content_type || 'application/octet-stream'
      let fileCategory = 'Unknown'
      if (mimeType.startsWith('image/')) fileCategory = 'Image'
      else if (mimeType.startsWith('video/')) fileCategory = 'Video'
      else if (mimeType.startsWith('audio/')) fileCategory = 'Audio'
      else if (mimeType.startsWith('text/')) fileCategory = 'Text'
      else if (mimeType.includes('pdf')) fileCategory = 'PDF Document'
      else if (mimeType.includes('word') || mimeType.includes('document')) fileCategory = 'Word Document'
      else if (mimeType.includes('excel') || mimeType.includes('spreadsheet')) fileCategory = 'Spreadsheet'
      else if (mimeType.includes('powerpoint') || mimeType.includes('presentation')) fileCategory = 'Presentation'
      else if (mimeType.includes('zip') || mimeType.includes('compressed') || mimeType.includes('archive')) fileCategory = 'Archive'
      else if (mimeType.includes('executable') || ext === 'exe' || ext === 'msi') fileCategory = 'Executable'
      else if (mimeType.includes('script') || ext === 'js' || ext === 'vbs' || ext === 'ps1') fileCategory = 'Script'

      // Check for potentially dangerous extensions
      const dangerousExts = ['exe', 'msi', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'jar', 'scr', 'pif', 'com', 'dll', 'hta', 'iso', 'img']
      const isDangerous = ext ? dangerousExts.includes(ext) : false

      return {
        filename,
        sizeLabel: formatBytes(attachment.size),
        sizeBytes: attachment.size,
        contentType: mimeType,
        sha256: attachment.sha256,
        contentId: attachment.content_id,
        extension: ext,
        fileCategory,
        isDangerous,
        isInline: !!attachment.content_id,
      }
    })
    return {
      total: attachments.length,
      samples,
      remaining: Math.max(0, attachments.length - samples.length),
    }
  })

  // Email sender details
  const senderDetails = computed(() => {
    const parsed = analysisResult.value?.parsed_email
    if (!parsed) return null

    const from = parsed.from as any
    const replyTo = parsed.reply_to as any

    return {
      displayName: from?.name || from?.display_name || null,
      email: from?.email || from?.address || (typeof parsed.from === 'string' ? parsed.from : null),
      domain: from?.domain || (from?.email?.split('@')[1]) || null,
      replyTo: replyTo?.email || replyTo?.address || (typeof parsed.reply_to === 'string' ? parsed.reply_to : null),
    }
  })

  // Email content summary
  const emailContent = computed(() => {
    const parsed = analysisResult.value?.parsed_email
    if (!parsed) return null

    // Helper to format recipient list
    const formatRecipients = (recipients: unknown): string | null => {
      if (!recipients) return null
      if (Array.isArray(recipients)) {
        const formatted = (recipients as any[]).map(r => r.email || r.address || r).filter(Boolean).join(', ')
        return formatted || null
      }
      if (typeof recipients === 'object') {
        return (recipients as any).email || (recipients as any).address || null
      }
      return typeof recipients === 'string' ? recipients : null
    }

    return {
      subject: parsed.subject as string || 'No Subject',
      to: Array.isArray(parsed.to)
        ? (parsed.to as any[]).map(t => t.email || t.address || t).join(', ')
        : (parsed.to as any)?.email || parsed.to as string || 'Unknown',
      cc: formatRecipients(parsed.cc),
      bcc: formatRecipients(parsed.bcc),
      returnPath: parsed.return_path as string || null,
      date: parsed.date as string || parsed.received_date as string || null,
      bodyPreview: (parsed.body_text as string || parsed.body_plain as string || '').slice(0, 300),
      hasHtml: !!(parsed.body_html || parsed.html_body),
    }
  })

  // Raw email content for different views
  const rawTextBody = computed(() => {
    const parsed = analysisResult.value?.parsed_email
    if (!parsed) return ''
    const body = parsed.body as any
    // Access body.plain_text from the backend schema
    return body?.plain_text || body?.text || body?.plain || parsed.body_text as string || parsed.body_plain as string || ''
  })

  const rawHtmlBody = computed(() => {
    const parsed = analysisResult.value?.parsed_email
    if (!parsed) return ''
    const body = parsed.body as any
    // Access body.html from the backend schema
    return body?.html || parsed.body_html as string || parsed.html_body as string || ''
  })

  const rawEmlContent = computed(() => {
    // raw_eml is at the root level of CombinedAnalysisResult
    return analysisResult.value?.raw_eml || ''
  })

  const mdmData = computed(() => {
    // Get the actual Message Data Model from Sublime's create_message response
    // The MDM structure is inside raw.data_model which contains: body, headers, sender, recipients, subject, type, etc.
    const mdm = analysisResult.value?.sublime?.mdm
    const raw = mdm?.raw as Record<string, unknown> | undefined
    // Return data_model which is the actual MDM matching Sublime's MDM documentation
    return raw?.data_model || null
  })

  // Processed HTML body with inline images (CID) replaced by base64 data
  const processedHtmlBody = computed(() => {
    const rawHtml = rawHtmlBody.value
    if (!rawHtml) return ''

    const attachments = (analysisResult.value?.parsed_email?.attachments ?? []) as EmailAttachment[]
    if (!attachments.length) return rawHtml

    let processed = rawHtml
    for (const att of attachments) {
      if (att.content_id && att.data && att.content_type?.startsWith('image/')) {
        // Remove angle brackets from Content-ID if present
        const cleanCid = att.content_id.replace(/^<|>$/g, '')
        // Replace all occurrences of cid:content_id
        const cidRegex = new RegExp(`cid:${cleanCid}`, 'gi')
        processed = processed.replace(cidRegex, `data:${att.content_type};base64,${att.data}`)
      }
    }
    return processed
  })

  const emailHeaders = computed(() => {
    const parsed = analysisResult.value?.parsed_email
    if (!parsed) return []
    return (parsed.headers as any[]) || []
  })

  return {
    attachmentSummary,
    senderDetails,
    emailContent,
    rawTextBody,
    rawHtmlBody,
    rawEmlContent,
    mdmData,
    emailHeaders,
    processedHtmlBody,
  }
}
