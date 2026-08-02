"""Tests for rate-limit visibility."""

from bsot.agent.budget import budget_status, estimate_duration


class TestBudgetStatus:
    def test_reports_every_known_service(self):
        status = budget_status()

        assert "virustotal" in status
        assert "abuseipdb" in status

    def test_virustotal_is_per_minute(self):
        """The constraint the model most needs to know about."""
        assert budget_status()["virustotal"]["requests_per_minute"] < 10


class TestEstimate:
    def test_small_batch_is_quick(self):
        assert estimate_duration("virustotal", 2) < 60

    def test_large_batch_is_slow(self):
        """50 IOCs at 4/min is over 12 minutes; the model must say so."""
        assert estimate_duration("virustotal", 50) > 600

    def test_unknown_service_uses_the_default(self):
        assert estimate_duration("not-a-service", 10) >= 0
