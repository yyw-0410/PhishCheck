"""AI Chat service using Gemini with analysis context and internet search."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Knowledge files directory
KNOWLEDGE_DIR = Path(__file__).parent.parent / "knowledge"

# Topic keywords to knowledge file mapping
KNOWLEDGE_TOPICS = {
    "user_guide.md": ["how to", "how do i", "use phishcheck", "upload", "guide", "help", "tutorial"],
    "privacy_summary.md": ["privacy", "data", "collect", "store", "retain", "gdpr", "personal information", "third-party", "third party"],
    "terms_summary.md": ["terms", "service", "liability", "disclaimer", "account", "terminate", "legal"],
    "email_analysis.md": ["email", "eml", "attack score", "sublime", "spf", "dkim", "dmarc", "authentication", "phishing", "detection rules", "pipeline"],
    "link_analysis.md": ["link", "url", "urlscan", "website", "domain", "ml classification", "redirect"],
    "file_analysis.md": ["file", "hash", "sha256", "md5", "malware", "sandbox", "hybrid analysis", "virustotal", "risk score", "verdict"],
}


@dataclass
class RAGResponse:
    """Response from the AI service."""
    answer: str
    sources: List[Dict[str, str]]
    model_used: str
    query: str


class RAGService:
    """AI service for answering questions about email analysis using Gemini."""
    
    def __init__(self, api_keys: Optional[List[str]] = None):
        # Support multiple API keys for failover
        self.api_keys = [k for k in (api_keys or []) if k]
        self._current_key_index = 0
        self._http_client: Optional[httpx.AsyncClient] = None
        # Instance-level caches (not class-level to avoid shared state across instances)
        self._knowledge_cache: Dict[str, str] = {}
        self._response_cache: Dict[str, str] = {}
    
    @property
    def api_key(self) -> Optional[str]:
        """Get current API key."""
        if not self.api_keys:
            return None
        return self.api_keys[self._current_key_index % len(self.api_keys)]
    
    def _get_key_label(self) -> str:
        """Get a label for the current API key (for logging)."""
        if not self.api_keys:
            return "none"
        key_num = (self._current_key_index % len(self.api_keys)) + 1
        return f"key_{key_num}"    
    def _rotate_key(self) -> bool:
        """Rotate to next API key. Returns True if there are more keys to try."""
        if len(self.api_keys) <= 1:
            return False
        old_key = self._get_key_label()
        self._current_key_index = (self._current_key_index + 1) % len(self.api_keys)
        new_key = self._get_key_label()
        logger.info(f"AI: Rotating from {old_key} to {new_key} due to rate limit")
        return True
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=15.0)  # Fast timeout
        return self._http_client
    
    async def close(self) -> None:
        if self._http_client and not self._http_client.is_closed:
            await self._http_client.aclose()
    

    
    def _get_relevant_knowledge(self, query: str) -> str:
        """Read the MOST relevant knowledge file based on user's question."""
        query_lower = query.lower()
        
        # Score each file by number of keyword matches
        best_file = None
        best_score = 0
        
        for filename, keywords in KNOWLEDGE_TOPICS.items():
            score = sum(1 for kw in keywords if kw in query_lower)
            if score > best_score:
                best_score = score
                best_file = filename
        
        if not best_file or best_score == 0:
            return ""
        
        # Use cache if available
        if best_file in self._knowledge_cache:
            logger.info(f"AI: Using cached knowledge from {best_file}")
            return self._knowledge_cache[best_file]
        
        # Read from file
        filepath = KNOWLEDGE_DIR / best_file
        if filepath.exists():
            try:
                content = filepath.read_text(encoding="utf-8")
                self._knowledge_cache[best_file] = content
                logger.info(f"AI: Loaded knowledge from {best_file}")
                return content
            except Exception as e:
                logger.warning(f"AI: Failed to read {best_file}: {e}")
        
        return ""
    
    def _redact_email(self, email: str) -> str:
        """Redact email address to protect privacy. john.doe@company.com -> j***@company.com"""
        if not email or '@' not in email:
            return email or 'N/A'
        local, domain = email.split('@', 1)
        if len(local) > 1:
            return f"{local[0]}***@{domain}"
        return f"***@{domain}"
    
    def _redact_url(self, url: str) -> str:
        """Redact URL path but keep domain for threat analysis."""
        try:
            parsed = urlparse(url)
            # Keep scheme and domain, redact path/query
            if parsed.path and len(parsed.path) > 1:
                return f"{parsed.scheme}://{parsed.netloc}/[path-redacted]"
            return f"{parsed.scheme}://{parsed.netloc}/"
        except (ValueError, AttributeError) as e:
            logger.debug(f"URL redaction failed: {e}")
            return "[url-redacted]"
    
    def _redact_subject(self, subject: str) -> str:
        """Convert subject to theme category only - don't send actual content."""
        if not subject:
            return '[no subject]'
        subj_lower = subject.lower()
        # Categorize by common phishing themes
        if any(w in subj_lower for w in ['invoice', 'payment', 'urgent', 'action required', 'verify', 'confirm', 'billing']):
            return '[financial/urgent themed]'
        elif any(w in subj_lower for w in ['password', 'account', 'security', 'suspended', 'locked', 'unusual', 'signin']):
            return '[account security themed]'
        elif any(w in subj_lower for w in ['delivery', 'package', 'shipping', 'order', 'tracking']):
            return '[delivery/order themed]'
        elif any(w in subj_lower for w in ['winner', 'prize', 'lottery', 'congratulations', 'selected']):
            return '[prize/lottery themed]'
        elif any(w in subj_lower for w in ['document', 'file', 'attachment', 'review', 'shared']):
            return '[document sharing themed]'
        else:
            return '[general/other themed]'
    
    def _redact_text_pii(self, text: str) -> str:
        """Redact PII from text content (email body, headers).
        
        Redacts:
        - Email addresses: john@example.com -> [email-redacted]
        - Phone numbers: 123-456-7890 -> [phone-redacted]
        - IP addresses: 192.168.1.1 -> [ip-redacted]
        """
        if not text:
            return text
        
        import re
        
        # Email pattern: name@domain.tld
        text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[email-redacted]', text)
        
        # Phone patterns: various formats
        text = re.sub(r'\+?1?[-.]?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}', '[phone-redacted]', text)
        
        # IP addresses: IPv4
        text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[ip-redacted]', text)
        
        return text
    
    def _build_prompt(self, query: str, analysis_context: Optional[Dict[str, Any]] = None) -> str:
        """Build the prompt for Gemini with analysis context (with PII redaction)."""
        
        # Always get relevant knowledge based on query (for grounding responses)
        knowledge_text = self._get_relevant_knowledge(query)
        
        # Format analysis context if provided
        context_text = ""
        if analysis_context:
            analysis_type = analysis_context.get("analysisType", "email")
            if analysis_type == "link":
                context_text = self._build_link_context(analysis_context)
            elif analysis_type == "file":
                context_text = self._build_file_context(analysis_context)
            else:
                context_text = self._build_email_context(analysis_context)

        # Simple, concise prompt with guidance on risk assessment
        parts = ['''You are PhishCheck AI, a security analysis assistant. Be concise.

IMPORTANT: When assessing email safety:
- Attack Score (0-100) is the PRIMARY indicator from ML analysis
- VT/VirusTotal detections are SECONDARY - single detections (1-2) are often FALSE POSITIVES
- Low attack score (0-20) with few VT detections = likely SAFE/legitimate
- Only flag as dangerous if attack score is high (40+) OR many VT detections (3+)''']
        
        if knowledge_text:
            parts.append(f"\nKnowledge:\n{knowledge_text}")
        
        if context_text:
            parts.append(f"\nAnalysis Data:\n{context_text}")
        
        parts.append(f"\nQuestion: {query}\n\nAnswer concisely in markdown:")
        
        return "\n".join(parts)
    
    def _build_email_context(self, analysis_context: Dict[str, Any]) -> str:
        """Build context text for email analysis."""
        context_text = "\n## Current Email Analysis Results:\n"
        
        # Email metadata (with PII redaction)
        if analysis_context.get("emailMetadata"):
            meta = analysis_context["emailMetadata"]
            # Apply PII redaction to protect user privacy
            redacted_subject = self._redact_subject(meta.get('subject', ''))
            redacted_from = self._redact_email(meta.get('from', ''))
            redacted_to = self._redact_email(meta.get('to', ''))
            context_text += f"""
### Email Metadata:
- **Subject:** {redacted_subject}
- **From:** {redacted_from}
- **To:** {redacted_to}
- **Date:** {meta.get('date', 'N/A')}
"""
        
        # Email body (with PII redaction)
        if analysis_context.get("emailBody"):
            redacted_body = self._redact_text_pii(analysis_context['emailBody'])
            context_text += f"\n### Email Body:\n```\n{redacted_body}\n```\n"
        
        # Important headers (with PII redaction)
        if analysis_context.get("headers"):
            headers = analysis_context["headers"]
            context_text += "\n### Important Headers:\n"
            for h in headers[:5]:
                redacted_value = self._redact_text_pii(h.get('value', 'N/A'))
                context_text += f"- **{h.get('name', 'Unknown')}:** {redacted_value}\n"
        
        # Attachments
        if analysis_context.get("attachments"):
            attachments = analysis_context["attachments"]
            context_text += f"\n### Attachments ({len(attachments)}):\n"
            for att in attachments[:10]:
                size_kb = round(att.get('size', 0) / 1024, 1)
                context_text += f"- `{att.get('filename', 'Unknown')}` ({att.get('contentType', 'Unknown')}, {size_kb}KB)\n"
        
        # Links found in body (with URL path redaction)
        if analysis_context.get("bodyLinks"):
            links = analysis_context["bodyLinks"]
            context_text += f"\n### Links in Email Body ({len(links)}):\n"
            for link in links[:10]:
                text = link.get('text', '')[:50]
                href = link.get('href', 'Unknown')
                # Redact URL paths to protect privacy while keeping domain for threat analysis
                redacted_href = self._redact_url(href) if href != 'Unknown' else href
                context_text += f"- [{text or 'Link'}]({redacted_href})\n"
        
        # Authentication results
        if analysis_context.get("authentication"):
            auth = analysis_context["authentication"]
            context_text += f"""
### Authentication Results:
- **SPF:** {auth.get('spf', 'N/A')}
- **DKIM:** {auth.get('dkim', 'N/A')}
- **DMARC:** {auth.get('dmarc', 'N/A')}
"""
        
        # Threat indicators (redacted - only show types and severity, not actual values)
        if analysis_context.get("threatIndicators"):
            threats = analysis_context["threatIndicators"]
            context_text += "\n### Threat Indicator Types Found:\n"
            # Group by type and count, don't send actual values
            type_counts = {}
            for threat in threats:
                t_type = threat.get('type', 'Unknown')
                severity = threat.get('severity', 'unknown')
                key = f"{t_type} ({severity})"
                type_counts[key] = type_counts.get(key, 0) + 1
            for key, count in list(type_counts.items())[:10]:
                context_text += f"- {count}x {key}\n"
        
        # Sublime rules triggered
        if analysis_context.get("sublimeRules"):
            rules = analysis_context["sublimeRules"]
            context_text += "\n### Detection Rules Triggered:\n"
            for rule in rules[:10]:  # Limit to 10
                context_text += f"- **{rule.get('name', 'Unknown')}** (Severity: {rule.get('severity', 'N/A')}): {rule.get('description', 'No description')}\n"
        
        # URLs found (count + domains for testing)
        if analysis_context.get("urlCount"):
            context_text += f"\n### URLs: {analysis_context['urlCount']} URL(s) found in the email\n"
            if analysis_context.get("domains"):
                context_text += f"- Domains: {', '.join(analysis_context['domains'][:5])}\n"
        
        # IP addresses (count + actual IPs for testing)
        if analysis_context.get("ipCount"):
            context_text += f"\n### IP Addresses: {analysis_context['ipCount']} unique IP(s) found\n"
            if analysis_context.get("ipAddresses"):
                context_text += f"- IPs: {', '.join(analysis_context['ipAddresses'][:5])}\n"
        
        # IPQS results (summary stats only)
        if analysis_context.get("ipqsSummary"):
            ipqs = analysis_context["ipqsSummary"]
            context_text += f"\n### IP Reputation Summary:\n"
            context_text += f"- {ipqs.get('total', 0)} IP(s) checked\n"
            if ipqs.get('highRisk'):
                context_text += f"- {ipqs['highRisk']} high-risk IP(s) (fraud score > 75)\n"
            if ipqs.get('vpnCount'):
                context_text += f"- {ipqs['vpnCount']} VPN IP(s)\n"
            if ipqs.get('proxyCount'):
                context_text += f"- {ipqs['proxyCount']} proxy IP(s)\n"
        
        # VirusTotal summary
        if analysis_context.get("virustotalSummary"):
            vt = analysis_context["virustotalSummary"]
            context_text += f"\n### VirusTotal Summary:\n"
            context_text += f"- {vt.get('total', 0)} indicator(s) checked\n"
            if vt.get('maliciousDetections'):
                context_text += f"- {vt['maliciousDetections']} malicious detection(s)\n"
            if vt.get('suspiciousDetections'):
                context_text += f"- {vt['suspiciousDetections']} suspicious detection(s)\n"
            # Show specific flagged indicators
            if vt.get('flaggedIndicators'):
                context_text += f"\n**Flagged Indicators:**\n"
                for fi in vt['flaggedIndicators'][:10]:
                    context_text += f"- `{fi.get('indicator', 'Unknown')}`: {fi.get('malicious', 0)} malicious, {fi.get('suspicious', 0)} suspicious\n"
        
        # Attack score
        if analysis_context.get("attackScore") is not None:
            context_text += f"\n### Overall Attack Score: {analysis_context['attackScore']}/100\n"
        
        # Verdict
        if analysis_context.get("verdict"):
            context_text += f"\n### Analysis Verdict: {analysis_context['verdict']}\n"
        
        return context_text
    
    def _build_link_context(self, analysis_context: Dict[str, Any]) -> str:
        """Build context text for link/URL analysis."""
        context_text = "\n## Current URL Analysis Results:\n"
        
        # URL being analyzed (redacted)
        if analysis_context.get("url"):
            context_text += f"\n### Analyzed URL: [URL redacted for privacy]\n"
        
        # URLscan results
        if analysis_context.get("urlscan"):
            urlscan = analysis_context["urlscan"]
            context_text += f"\n### URLscan.io Results:\n"
            context_text += f"- **Verdict:** {urlscan.get('verdict', 'N/A')}\n"
            tags = urlscan.get('tags', [])
            if tags:
                context_text += f"- **Tags:** {', '.join(tags[:5])}\n"
        
        # Sublime ML results
        if analysis_context.get("sublimeMl"):
            ml = analysis_context["sublimeMl"]
            context_text += f"\n### Sublime ML Analysis:\n"
            context_text += f"- **Classification:** {ml.get('label', 'N/A')}\n"
            if ml.get('score') is not None:
                context_text += f"- **Risk Score:** {int(ml.get('score', 0) * 100)}%\n"
            if ml.get('containsLogin'):
                context_text += f"- **Contains Login Form:** Yes\n"
            if ml.get('containsCaptcha'):
                context_text += f"- **Contains CAPTCHA:** Yes\n"
            if ml.get('redirectCount'):
                context_text += f"- **Redirects:** {ml.get('redirectCount')}\n"
        
        # VirusTotal results
        if analysis_context.get("virustotal"):
            vt = analysis_context["virustotal"]
            context_text += f"\n### VirusTotal Results:\n"
            context_text += f"- **Malicious:** {vt.get('malicious', 0)} detections\n"
            context_text += f"- **Suspicious:** {vt.get('suspicious', 0)} detections\n"
        
        return context_text
    
    def _build_file_context(self, analysis_context: Dict[str, Any]) -> str:
        """Build context text for file analysis."""
        context_text = "\n## Current File Analysis Results:\n"
        
        # File info (redacted)
        if analysis_context.get("fileInfo"):
            info = analysis_context["fileInfo"]
            context_text += f"\n### File Information:\n"
            if info.get('contentType'):
                context_text += f"- **Type:** {info.get('contentType')}\n"
            # Don't include filename or hashes for privacy
        
        # Overall verdict
        if analysis_context.get("verdict"):
            context_text += f"\n### Overall Verdict: {analysis_context['verdict']}\n"
        
        if analysis_context.get("riskScore") is not None:
            context_text += f"### Risk Score: {analysis_context['riskScore']}\n"
        
        # VirusTotal results
        if analysis_context.get("virustotal"):
            vt = analysis_context["virustotal"]
            context_text += f"\n### VirusTotal Results:\n"
            context_text += f"- **Malicious:** {vt.get('malicious', 0)} detections\n"
            context_text += f"- **Suspicious:** {vt.get('suspicious', 0)} detections\n"
            if vt.get('total'):
                context_text += f"- **Total Scanners:** {vt.get('total')}\n"
        
        # Hybrid Analysis results - Enhanced
        if analysis_context.get("hybridAnalysis"):
            ha = analysis_context["hybridAnalysis"]
            context_text += f"\n### Hybrid Analysis (Sandbox):\n"
            context_text += f"- **Verdict:** {ha.get('verdict', 'N/A')}\n"
            if ha.get('threatScore') is not None:
                context_text += f"- **Threat Score:** {ha.get('threatScore')}/100\n"
            if ha.get('avDetections') is not None:
                context_text += f"- **AV Detections:** {ha.get('avDetections')}\n"
            if ha.get('malwareFamily'):
                context_text += f"- **Malware Family:** {ha.get('malwareFamily')}\n"
            if ha.get('fileType'):
                context_text += f"- **File Type:** {ha.get('fileType')}\n"
            
            # Behavioral data
            behavioral_info = []
            if ha.get('totalProcesses') is not None:
                behavioral_info.append(f"{ha.get('totalProcesses')} processes")
            if ha.get('totalSignatures') is not None:
                behavioral_info.append(f"{ha.get('totalSignatures')} signatures")
            if ha.get('totalNetworkConnections') is not None:
                behavioral_info.append(f"{ha.get('totalNetworkConnections')} network connections")
            if behavioral_info:
                context_text += f"- **Behavioral:** {', '.join(behavioral_info)}\n"
            
            # Tags
            if ha.get('tags'):
                context_text += f"- **Tags:** {', '.join(ha.get('tags')[:10])}\n"
            if ha.get('classificationTags'):
                context_text += f"- **Classification:** {', '.join(ha.get('classificationTags')[:5])}\n"
            
            # Network indicators
            if ha.get('domainsContacted'):
                context_text += f"- **Domains Contacted:** {', '.join(ha.get('domainsContacted')[:5])}\n"
            if ha.get('hostsContacted'):
                context_text += f"- **IPs Contacted:** {', '.join(ha.get('hostsContacted')[:5])}\n"
            
            # MITRE ATT&CK
            if ha.get('mitreAttacks'):
                context_text += f"- **MITRE ATT&CK Techniques:** {', '.join(ha.get('mitreAttacks')[:5])}\n"
            
            if ha.get('reportUrl'):
                context_text += f"- **Full Report:** {ha.get('reportUrl')}\n"
        
        return context_text

    async def _call_gemini(self, prompt: str) -> str:
        """Call Google Gemini API with internet search (grounding) enabled."""
        if not self.api_key:
            raise ValueError("AI service unavailable. Please contact the administrator.")
        
        client = await self._get_client()
        
        # Try models in order - newest to oldest
        # use_search=True enables Google Search grounding for real-time info
        models_to_try = [
            ("gemini-3-flash-preview", True),     # Gemini 3 (newest) with Google Search
            ("gemini-2.5-flash", True),           # Stable fallback with Google Search
            ("gemini-2.0-flash", False),          # Legacy fallback (no grounding)
        ]
        
        last_error = None
        for model, use_search in models_to_try:
            logger.info(f"AI: Using {self._get_key_label()} with model {model}")
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
            
            request_body = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }],
                "generationConfig": {
                    "temperature": 0.5,          # Lower = faster, more focused
                    "maxOutputTokens": 1024,     # Reduced from 4096 for speed
                    "topP": 0.8,
                    "topK": 40
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
                ]
            }
            
            # Add google_search tool only if supported
            if use_search:
                request_body["tools"] = [{"google_search": {}}]
            
            # Retry logic for rate limits (429)
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = await client.post(
                        url,
                        headers={"Content-Type": "application/json"},
                        json=request_body
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        # Extract text from Gemini response
                        if "candidates" in data and len(data["candidates"]) > 0:
                            candidate = data["candidates"][0]
                            # Check for blocked content
                            if candidate.get("finishReason") == "SAFETY":
                                logger.warning(f"AI: Response blocked by safety filter for model {model}")
                                last_error = "Content filtered for safety. Please rephrase your question."
                                break  # Try next model
                            if "content" in candidate and "parts" in candidate["content"]:
                                # Combine all text parts
                                text_parts = []
                                for part in candidate["content"]["parts"]:
                                    if "text" in part:
                                        text_parts.append(part["text"])
                                if text_parts:
                                    return "\n".join(text_parts)
                        # Log the actual response for debugging
                        logger.warning(f"AI: Empty response from {model}. Response data: {data}")
                        last_error = "AI service returned an empty response. Please try again."
                        break  # Exit retry loop and try next model
                    elif response.status_code == 429:
                        # Rate limit - try rotating to next API key first
                        if self._rotate_key():
                            # Rotated to a new key, retry immediately with new key
                            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
                            continue
                        # No more keys, retry with exponential backoff
                        if attempt < max_retries - 1:
                            import asyncio
                            wait_time = (2 ** attempt) + 1  # 2s, 3s, 5s
                            await asyncio.sleep(wait_time)
                            continue
                        last_error = "AI service is temporarily busy. Please wait a moment and try again."
                    elif response.status_code in [401, 403]:
                        last_error = "AI service authentication failed. Please contact the administrator."
                        raise ValueError(last_error)
                    elif response.status_code >= 500:
                        # Server error - retry
                        if attempt < max_retries - 1:
                            import asyncio
                            await asyncio.sleep(2)
                            continue
                        last_error = "AI service is temporarily unavailable. Please try again later."
                    else:
                        last_error = "AI service encountered an error. Please try again."
                        break  # Don't retry on other errors
                        
                except ValueError:
                    raise
                except Exception as e:
                    if attempt < max_retries - 1:
                        import asyncio
                        await asyncio.sleep(1)
                        continue
                    last_error = "AI service connection failed. Please check your network and try again."
                
                break  # Exit retry loop if we didn't continue
        
        raise ValueError(last_error or "All AI models failed")


    
    async def ask(self, query: str, analysis_context: Optional[Dict[str, Any]] = None, 
                  conversation_history: Optional[List[Dict[str, str]]] = None) -> RAGResponse:
        """Process a question using Gemini with analysis context and conversation history."""
        
        # Check cache for simple questions (no analysis context, no history)
        cache_key = query.lower().strip()
        if not analysis_context and not conversation_history and cache_key in self._response_cache:
            logger.info("AI: Using cached response")
            return RAGResponse(
                answer=self._response_cache[cache_key],
                sources=[],
                model_used="cache",
                query=query
            )
        
        # Build prompt with analysis context
        prompt = self._build_prompt(query, analysis_context)
        
        # Add conversation history if provided (limited to last 4 messages for speed)
        if conversation_history and len(conversation_history) > 0:
            history_text = "\n\nRecent conversation:\n"
            for msg in conversation_history[-4:]:  # Reduced from 8 to 4
                role = "Q" if msg.get("role") == "user" else "A"
                content = msg.get("content", "")[:200]  # Reduced from 500 to 200
                history_text += f"{role}: {content}\n"
            prompt = prompt.replace("Question:", f"{history_text}\nQuestion:")
        
        # Generate response using Gemini
        answer = await self._call_gemini(prompt)
        
        # Cache simple responses (no analysis context)
        if not analysis_context and not conversation_history:
            self._response_cache[cache_key] = answer
        
        return RAGResponse(
            answer=answer,
            sources=[],
            model_used="gemini-flash",
            query=query
        )
    
    def get_suggested_questions(self) -> List[str]:
        """Return a list of general suggested questions users can ask."""
        return [
            "What is phishing?",
            "How can I identify a phishing email?",
            "What are SPF, DKIM, and DMARC?",
            "What should I do if I clicked a phishing link?"
        ]
    
    def get_analysis_questions(self) -> List[str]:
        """Return suggested questions specific to the current analysis."""
        return [
            "Is this email safe?",
            "What threats were detected?",
            "Explain the authentication results",
            "What should I do about this email?"
        ]


# Singleton instance
_rag_service: Optional[RAGService] = None


def get_rag_service() -> RAGService:
    """Get or create the RAG service singleton."""
    global _rag_service
    if _rag_service is None:
        settings = get_settings()
        # Load all available API keys
        api_keys = [
            getattr(settings, 'ai_api_key', None),
            getattr(settings, 'ai_api_key_2', None),
        ]
        _rag_service = RAGService(api_keys=api_keys)
    return _rag_service
