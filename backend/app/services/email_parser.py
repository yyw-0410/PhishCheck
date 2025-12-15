"""Email parsing and normalization service."""

from __future__ import annotations

import hashlib
import quopri
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from datetime import datetime
from typing import List, Optional, Sequence, Tuple, Union
import nh3

from app.schemas import (
    EmailAddress,
    EmailAttachment,
    EmailAuthentication,
    EmailBody,
    EmailHeader,
    EmailLink,
    ParsedEmail,
)

_URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


def _decode_quoted_printable(content: str) -> str:
    """Decode quoted-printable encoded content.
    
    Handles:
    - Soft line breaks (=\r\n or =\n) - removes them to join split content
    - Hex-encoded characters (=3D -> =, =20 -> space, etc.)
    """
    if not content:
        return content
    
    try:
        # First, remove soft line breaks (= followed by line break)
        # This is critical for URLs split across lines
        import re
        content = re.sub(r'=\r?\n', '', content)
        
        # Now decode the remaining QP sequences (=XX hex codes)
        decoded_bytes = quopri.decodestring(content.encode('latin-1', errors='replace'))
        return decoded_bytes.decode('utf-8', errors='replace')
    except Exception:
        # If decoding fails, return original
        return content


def _normalize_url(url: str) -> Optional[str]:
    """Validate and clean up extracted URLs.
    
    Removes QP artifacts, decodes HTML entities, and validates URL structure.
    """
    if not url:
        return None
    
    # Decode HTML entities first (e.g., &amp; -> &, &lt; -> <)
    import html
    cleaned = html.unescape(url)
    
    # Strip whitespace and common trailing punctuation
    cleaned = cleaned.strip().rstrip(".,;:!?\"')")
    
    # Remove trailing = from quoted-printable soft line breaks
    while cleaned.endswith('='):
        cleaned = cleaned[:-1]
    
    # Remove trailing ?= or &= (incomplete query params from QP encoding)
    if cleaned.endswith('?') or cleaned.endswith('&'):
        cleaned = cleaned[:-1]
    
    # Must start with http:// or https://
    if not cleaned.startswith(('http://', 'https://')):
        return None
    
    # Use urlparse to validate and check for truncation
    try:
        from urllib.parse import urlparse
        parsed = urlparse(cleaned)
        
        # Must have a valid netloc (domain)
        if not parsed.netloc:
            return None
        
        # Domain must contain at least one dot (e.g., "example.com")
        # Exception: localhost is valid
        if '.' not in parsed.netloc and parsed.netloc.lower() != 'localhost':
            return None
        
        # Filter out URLs that look truncated (path ends with = or just /=)
        if parsed.path.endswith('=') or parsed.path == '/=':
            return None
        
        return cleaned
    except Exception:
        return None




class _HTMLLinkExtractor(HTMLParser):
    """Collect anchor tags and their text content."""

    def __init__(self) -> None:
        super().__init__()
        self._current: Optional[dict] = None
        self.links: List[Tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if not href:
            return
        self._current = {"href": href, "text": ""}

    def handle_data(self, data: str) -> None:
        if self._current is None:
            return
        self._current["text"] += data

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or self._current is None:
            return
        href = self._current["href"]
        text = self._current["text"].strip() or None
        self.links.append((href, text or ""))
        self._current = None


def _ensure_bytes(raw: Union[bytes, str]) -> bytes:
    if isinstance(raw, bytes):
        return raw
    return raw.encode("utf-8", errors="replace")


def _parse_addresses(raw: Optional[str]) -> List[EmailAddress]:
    if not raw:
        return []
    addresses = []
    for name, address in getaddresses([raw]):
        if not address:
            continue
        addresses.append(EmailAddress(name=name or None, address=address))
    return addresses


def _collect_body_parts(message: EmailMessage) -> Tuple[Optional[str], Optional[str]]:
    plain_segments: List[str] = []
    html_segments: List[str] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        if disposition in {"attachment"}:
            continue

        try:
            payload = part.get_content()
        except LookupError:
            payload = part.get_payload(decode=True) or b""

        if isinstance(payload, bytes):
            charset = part.get_content_charset("utf-8")
            payload = payload.decode(charset, errors="replace")

        if content_type == "text/plain":
            plain_segments.append(payload)
        elif content_type == "text/html":
            html_segments.append(payload)

    plain_text = "\n".join(segment.strip() for segment in plain_segments if segment.strip()) or None
    html_body = "\n".join(html_segments) or None

    return plain_text, html_body


def _sanitize_html(html_body: Optional[str]) -> Optional[str]:
    """Sanitize HTML using nh3 (fast Rust-based sanitizer)."""
    if not html_body:
        return None
    
    # nh3 uses sets for tags and dict with sets for attributes
    allowed_tags = {
        "a", "abbr", "b", "blockquote", "br", "code", "div", "em", "i",
        "li", "ol", "p", "pre", "span", "strong", "table", "tbody",
        "td", "th", "thead", "tr", "u", "ul",
    }
    allowed_attrs = {
        "a": {"href", "title"},
        "td": {"colspan", "rowspan"},
        "th": {"colspan", "rowspan"},
    }
    
    cleaned = nh3.clean(
        html_body,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip_comments=True,
    )
    return cleaned or None


def _extract_attachments(message: EmailMessage) -> List[EmailAttachment]:
    import base64
    
    attachments: List[EmailAttachment] = []
    for part in message.walk():
        if part.is_multipart():
            continue

        disposition = part.get_content_disposition()
        filename = part.get_filename()
        content_type = part.get_content_type()
        
        # Also include inline images (for QR code scanning)
        is_attachment = disposition == "attachment" or (disposition == "inline" and filename)
        is_inline_image = content_type.startswith('image/') and disposition == "inline"
        
        if not is_attachment and not is_inline_image:
            continue

        payload = part.get_payload(decode=True) or b""
        
        # Store base64 data for image attachments (for QR code scanning)
        data_b64 = None
        if content_type.startswith('image/'):
            data_b64 = base64.b64encode(payload).decode('ascii')
        
        attachments.append(
            EmailAttachment(
                filename=filename,
                content_type=content_type,
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                content_id=part.get("Content-ID"),
                data=data_b64,
            )
        )
    return attachments


def _gather_links(
    plain_text: Optional[str], 
    html_body: Optional[str],
    attachments: Optional[List[EmailAttachment]] = None
) -> List[EmailLink]:
    """Extract links from email content. Content should already be QP-decoded."""
    links: List[EmailLink] = []
    seen_hrefs: set = set()  # Track seen URLs to deduplicate

    # 1. Extract from plain text body
    if plain_text:
        for match in _URL_REGEX.finditer(plain_text):
            raw_href = match.group(0).rstrip(").,\"'")
            href = _normalize_url(raw_href)
            if not href or href in seen_hrefs:
                continue
            seen_hrefs.add(href)
            snippet_start = max(0, match.start() - 40)
            snippet_end = min(len(plain_text), match.end() + 40)
            context = plain_text[snippet_start:snippet_end].strip()
            links.append(EmailLink(href=href, text=None, context=context or None))

    # 2. Extract from HTML anchor tags (gets link text)
    if html_body:
        parser = _HTMLLinkExtractor()
        parser.feed(html_body)
        for raw_href, text in parser.links:
            href = _normalize_url(raw_href)
            if not href or href in seen_hrefs:
                continue
            seen_hrefs.add(href)
            links.append(EmailLink(href=href, text=text or None, context=None))

    # 3. Also extract ALL plain text URLs from HTML body (catches URLs not in anchor tags)
    if html_body:
        for match in _URL_REGEX.finditer(html_body):
            raw_href = match.group(0).rstrip(").,\"'")
            href = _normalize_url(raw_href)
            if not href or href in seen_hrefs:
                continue
            seen_hrefs.add(href)
            links.append(EmailLink(href=href, text=None, context="Found in HTML body"))

    # 4. Scan image attachments for QR codes (Quishing detection)
    if attachments:
        try:
            from app.services.qr_scanner import QRCodeScanner
            scanner = QRCodeScanner()
            
            for attachment in attachments:
                # Only scan image attachments
                if not attachment.content_type or not attachment.content_type.startswith('image/'):
                    continue
                
                # Get attachment data
                if not attachment.data:
                    continue
                
                # Decode base64 if needed
                import base64
                try:
                    if isinstance(attachment.data, str):
                        image_data = base64.b64decode(attachment.data)
                    else:
                        image_data = attachment.data
                except Exception:
                    continue
                
                # Scan for QR codes
                qr_urls = scanner.scan_image_bytes(image_data)
                for url in qr_urls:
                    if url in seen_hrefs:
                        continue
                    seen_hrefs.add(url)
                    links.append(EmailLink(
                        href=url, 
                        text=None, 
                        context=f"Found in QR code ({attachment.filename or 'image'})"
                    ))
        except ImportError:
            pass  # QR scanning not available

    return links




def _extract_authentication(message: EmailMessage) -> Optional[EmailAuthentication]:
    """Extract SPF, DKIM, and DMARC results from Authentication-Results header."""
    auth_header = message.get("Authentication-Results")
    if not auth_header:
        # Try alternative headers that some mail systems use
        auth_header = message.get("X-Authentication-Results")
    
    if not auth_header:
        return None
    
    # Parse the header - it can be multi-line and complex
    # Example: mx.google.com; dkim=pass header.i=@example.com; spf=pass; dmarc=pass
    auth_lower = auth_header.lower()
    
    spf = None
    dkim = None
    dmarc = None
    
    # Extract SPF result
    spf_match = re.search(r'\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)', auth_lower)
    if spf_match:
        spf = spf_match.group(1)
    
    # Extract DKIM result
    dkim_match = re.search(r'\bdkim\s*=\s*(pass|fail|none|neutral|temperror|permerror)', auth_lower)
    if dkim_match:
        dkim = dkim_match.group(1)
    
    # Extract DMARC result
    dmarc_match = re.search(r'\bdmarc\s*=\s*(pass|fail|none|bestguesspass)', auth_lower)
    if dmarc_match:
        dmarc = dmarc_match.group(1)
    
    # Only return if we found at least one result
    if spf or dkim or dmarc:
        return EmailAuthentication(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
            raw_header=auth_header[:500] if len(auth_header) > 500 else auth_header  # Limit raw header size
        )
    
    return None


class EmailParserService:
    """Parse raw email artifacts into a normalized representation."""

    def parse(self, raw_message: Union[bytes, str]) -> ParsedEmail:
        """Parse an RFC 5322 email message into a structured representation."""
        message_bytes = _ensure_bytes(raw_message)
        email_message = BytesParser(policy=policy.default).parsebytes(message_bytes)

        plain_text, html_body = _collect_body_parts(email_message)
        
        # Decode quoted-printable BEFORE sanitization (critical for URL extraction)
        # Some emails have QP-encoded content without proper Content-Transfer-Encoding header
        decoded_html = _decode_quoted_printable(html_body) if html_body else None
        decoded_plain = _decode_quoted_printable(plain_text) if plain_text else None
        
        sanitized_html = _sanitize_html(decoded_html)

        # Extract return path - clean angle brackets if present
        return_path_raw = email_message.get("Return-Path")
        return_path = None
        if return_path_raw:
            return_path = return_path_raw.strip().strip("<>").strip() or None

        # Extract attachments first so we can scan them for QR codes
        attachments = _extract_attachments(email_message)
        
        parsed = ParsedEmail(
            message_id=email_message.get("Message-ID"),
            subject=email_message.get("Subject"),
            date=_safe_parse_date(email_message.get("Date")),
            from_=_first_or_none(_parse_addresses(email_message.get("From"))),
            reply_to=_first_or_none(_parse_addresses(email_message.get("Reply-To"))),
            return_path=return_path,
            to=_parse_addresses(email_message.get("To")),
            cc=_parse_addresses(email_message.get("Cc")),
            bcc=_parse_addresses(email_message.get("Bcc")),
            headers=[EmailHeader(name=name, value=value) for name, value in email_message.items()],
            body=EmailBody(plain_text=decoded_plain or plain_text, html=html_body, sanitized_html=sanitized_html),
            attachments=attachments,
            # Pass decoded HTML for link extraction (already QP-decoded)
            links=_gather_links(decoded_plain, decoded_html, attachments),
            authentication=_extract_authentication(email_message),
        )

        return parsed


def _first_or_none(addresses: Sequence[EmailAddress]) -> Optional[EmailAddress]:
    return addresses[0] if addresses else None


def _safe_parse_date(raw_date: Optional[str]) -> Optional[datetime]:
    if not raw_date:
        return None
    try:
        return parsedate_to_datetime(raw_date)
    except (TypeError, ValueError):
        return None
