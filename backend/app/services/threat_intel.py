"""Threat intelligence enrichment service placeholder."""


class ThreatIntelService:
    """Coordinate lookups against third-party threat intelligence providers."""

    def enrich(self, artifact: dict) -> dict:
        """TODO: perform enrichment using providers such as VirusTotal or custom APIs."""
        raise NotImplementedError("Threat intelligence enrichment not implemented yet.")
