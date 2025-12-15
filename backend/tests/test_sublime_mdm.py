"""Ensure Sublime metadata models accept representative payloads."""

from datetime import datetime, timezone

from app.schemas import (
    EmailAttachment,
    EmailBody,
    EmailHeader,
    EmailLink,
    SublimeDetection,
    SublimeIndicator,
    SublimeMDM,
    SublimeVerdict,
    SublimeVerdictReason,
)


def test_sublime_mdm_round_trip():
    mdm = SublimeMDM(
        analysis_id="analysis-123",
        status="complete",
        submitted_at=datetime(2024, 10, 1, 12, 0, tzinfo=timezone.utc),
        completed_at=datetime(2024, 10, 1, 12, 1, tzinfo=timezone.utc),
        engine_version="2024.09.15",
        verdict=SublimeVerdict(
            label="MALICIOUS",
            score=0.92,
            confidence="high",
            reasons=[
                SublimeVerdictReason(
                    rule_id="rule-abc",
                    title="Credential phishing detected",
                    description="Login page hosted on suspicious domain.",
                    reference_url="https://docs.sublime.security/rule-abc",
                )
            ],
        ),
        detections=[
            SublimeDetection(
                id="det-1",
                title="Suspicious Link",
                description="Message contains link to lookalike domain.",
                severity="high",
                indicators=[
                    SublimeIndicator(
                        type="url",
                        value="http://login.example.co",
                        verdict="malicious",
                        details="Domain registered 1 day ago.",
                    )
                ],
            )
        ],
        indicators=[
            SublimeIndicator(
                type="domain",
                value="example.co",
                verdict="malicious",
                details="Matches known credential harvesting infrastructure.",
            )
        ],
        message_subject="Important security notice",
        message_sender="Security Team <alerts@example.com>",
        headers=[EmailHeader(name="From", value="alerts@example.com")],
        body=EmailBody(
            plain_text="Go to http://login.example.co",
            html="<p>Go to <a href='http://login.example.co'>login</a></p>",
            sanitized_html="<p>Go to <a href=\"http://login.example.co\">login</a></p>",
        ),
        links=[EmailLink(href="http://login.example.co", text="login")],
        attachments=[
            EmailAttachment(
                filename="policy.pdf",
                content_type="application/pdf",
                size=1024,
                sha256="a" * 64,
            )
        ],
        raw={"verdict": {"label": "MALICIOUS"}},
    )

    assert mdm.verdict.label == "MALICIOUS"
    assert mdm.detections[0].indicators[0].value == "http://login.example.co"
    assert mdm.links[0].href.startswith("http://")
