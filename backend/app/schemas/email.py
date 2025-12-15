"""Schemas describing parsed email artifacts and analysis results."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, ConfigDict


class EmailAddress(BaseModel):
    """Normalized representation of an email address."""

    name: Optional[str] = Field(default=None, description="Display name if provided.")
    address: str = Field(description="RFC 5322 email address.")


class EmailHeader(BaseModel):
    """Key-value header pair."""

    name: str = Field(description="Header name.")
    value: str = Field(description="Header value.")


class EmailAttachment(BaseModel):
    """Metadata for an extracted email attachment."""

    filename: Optional[str] = Field(default=None, description="Original filename.")
    content_type: str = Field(description="MIME type of the attachment.")
    size: int = Field(description="Attachment size in bytes.")
    sha256: str = Field(description="SHA-256 hash of the attachment content.")
    content_id: Optional[str] = Field(default=None, description="CID for inline attachments.")
    data: Optional[str] = Field(default=None, description="Base64-encoded attachment content for image scanning.")


class EmailBody(BaseModel):
    """Structured access to email body content."""

    plain_text: Optional[str] = Field(default=None, description="Text/plain body.")
    html: Optional[str] = Field(default=None, description="Original HTML body.")
    sanitized_html: Optional[str] = Field(
        default=None, description="HTML body after sanitization for safe display."
    )


class EmailLink(BaseModel):
    """Hyperlink extracted from the message."""

    href: str = Field(description="URL target.")
    text: Optional[str] = Field(default=None, description="Visible link text if available.")
    context: Optional[str] = Field(
        default=None,
        description="Snippet of surrounding text to aid analysts.",
    )


class EmailAuthentication(BaseModel):
    """Email authentication results from Authentication-Results header."""

    spf: Optional[str] = Field(default=None, description="SPF result (pass/fail/softfail/neutral/none).")
    dkim: Optional[str] = Field(default=None, description="DKIM result (pass/fail/none).")
    dmarc: Optional[str] = Field(default=None, description="DMARC result (pass/fail/none).")
    raw_header: Optional[str] = Field(default=None, description="Raw Authentication-Results header.")


class ParsedEmail(BaseModel):
    """Aggregate view of a parsed email artifact."""

    model_config = ConfigDict(populate_by_name=True)

    message_id: Optional[str] = Field(default=None, description="RFC 5322 Message-ID header.")
    subject: Optional[str] = Field(default=None, description="Subject line.")
    date: Optional[datetime] = Field(default=None, description="Parsed Date header.")
    from_: Optional[EmailAddress] = Field(
        default=None, alias="from", description="Sender address if available."
    )
    reply_to: Optional[EmailAddress] = Field(
        default=None, description="Reply-To address if supplied."
    )
    return_path: Optional[str] = Field(
        default=None, description="Return-Path header (envelope sender/bounce address)."
    )
    to: List[EmailAddress] = Field(default_factory=list, description="Primary recipients.")
    cc: List[EmailAddress] = Field(default_factory=list, description="Carbon-copy recipients.")
    bcc: List[EmailAddress] = Field(default_factory=list, description="Blind carbon copy recipients.")
    headers: List[EmailHeader] = Field(default_factory=list, description="All message headers.")
    body: EmailBody = Field(description="Body content.")
    attachments: List[EmailAttachment] = Field(
        default_factory=list, description="Attachments discovered in the message."
    )
    links: List[EmailLink] = Field(default_factory=list, description="Extracted hyperlinks.")
    authentication: Optional[EmailAuthentication] = Field(
        default=None, description="SPF/DKIM/DMARC authentication results."
    )
