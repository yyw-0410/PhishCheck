"""Tests for the email parsing service."""

from __future__ import annotations

import hashlib
from textwrap import dedent

from app.services.email_parser import EmailParserService


def _build_service() -> EmailParserService:
    return EmailParserService()


def test_parse_multipart_email_with_attachment():
    raw_message = dedent(
        """\
        From: Alice Example <alice@example.com>
        To: Bob Example <bob@example.com>
        Subject: Quarterly Update
        Message-ID: <1234@example.com>
        Date: Tue, 15 Oct 2024 12:34:56 -0400
        MIME-Version: 1.0
        Content-Type: multipart/mixed; boundary="BOUNDARY"

        --BOUNDARY
        Content-Type: multipart/alternative; boundary="ALT"

        --ALT
        Content-Type: text/plain; charset="utf-8"

        Hello Bob,
        Check https://example.com/login.

        --ALT
        Content-Type: text/html; charset="utf-8"

        <html>
          <body>
            <p>Hello Bob,</p>
            <p>Please <a href="https://example.com/login">verify</a> your account.</p>
          </body>
        </html>

        --ALT--

        --BOUNDARY
        Content-Type: text/plain; charset="utf-8"
        Content-Disposition: attachment; filename="note.txt"
        Content-Transfer-Encoding: base64

        SGVsbG8gZnJvbSBhdHRhY2htZW50IQ==

        --BOUNDARY--
        """
    ).encode("utf-8")

    parser = _build_service()
    parsed = parser.parse(raw_message)

    assert parsed.subject == "Quarterly Update"
    assert parsed.from_ and parsed.from_.address == "alice@example.com"
    assert parsed.to and parsed.to[0].address == "bob@example.com"
    assert parsed.body.plain_text and "Hello Bob" in parsed.body.plain_text
    assert parsed.body.html and "<a href=" in parsed.body.html
    assert parsed.body.sanitized_html and "<script" not in parsed.body.sanitized_html
    assert parsed.attachments

    attachment = parsed.attachments[0]
    assert attachment.filename == "note.txt"
    assert attachment.content_type == "text/plain"
    assert attachment.size == len("Hello from attachment!".encode("utf-8"))
    expected_hash = hashlib.sha256(b"Hello from attachment!").hexdigest()
    assert attachment.sha256 == expected_hash

    hrefs = {link.href for link in parsed.links}
    assert "https://example.com/login" in hrefs

    assert parsed.date and parsed.date.year == 2024


def test_html_only_email_is_sanitized_and_links_extracted():
    raw_message = dedent(
        """\
        From: "Security Team" <alert@example.com>
        To: victim@example.com
        Subject: Immediate Action Required
        Date: Wed, 16 Oct 2024 08:00:00 +0000
        MIME-Version: 1.0
        Content-Type: text/html; charset="utf-8"

        <html>
          <body>
            <script>alert("xss");</script>
            <p>Your account has issues. Visit
               <a href="http://malicious.example.com/reset">this page</a>
               to resolve them.</p>
          </body>
        </html>
        """
    ).encode("utf-8")

    parser = _build_service()
    parsed = parser.parse(raw_message)

    assert parsed.body.plain_text is None
    assert parsed.body.html and "script" in parsed.body.html
    assert parsed.body.sanitized_html and "script" not in parsed.body.sanitized_html.lower()

    hrefs = [link.href for link in parsed.links]
    assert "http://malicious.example.com/reset" in hrefs

    # HTML link text should be captured.
    link = next(link for link in parsed.links if link.href == "http://malicious.example.com/reset")
    assert link.text == "this page"

    # No attachments should be present.
    assert parsed.attachments == []
