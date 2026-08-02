"""Tests for rate-limit visibility."""

import pytest

from bsot.agent.budget import budget_status, estimate_duration


class TestBudgetStatus:
    def test_reports_every_known_service(self):
        status = budget_status()

        assert "virustotal" in status
        assert "abuseipdb" in status

    def test_virustotal_is_per_minute(self):
        """The constraint the model most needs to know about."""
        status = budget_status()["virustotal"]
        # Assert both values to catch a swap; exact values catch division/multiplication errors
        # Use rel tolerance to account for rounding to 4 decimal places
        assert status["requests_per_second"] == pytest.approx(4 / 60, rel=1e-3)
        assert status["requests_per_minute"] == pytest.approx(4.0)


class TestEstimate:
    def test_small_batch_is_quick(self):
        # Within burst; should return 0
        assert estimate_duration("virustotal", 2) == 0.0

    def test_at_burst_boundary(self):
        # Exactly at burst (4); should return 0
        assert estimate_duration("virustotal", 4) == 0.0

    def test_one_past_burst(self):
        # One past burst (5); should be (5-4)/(4/60) = 1*60/4 = 15 seconds
        assert estimate_duration("virustotal", 5) == pytest.approx(15.0)

    def test_large_batch_is_slow(self):
        """50 IOCs at 4/min is over 11.5 minutes; the model must say so."""
        # (50-4)/(4/60) = 46*60/4 = 690 seconds = 11.5 minutes
        assert estimate_duration("virustotal", 50) == pytest.approx(690.0)

    def test_unknown_service_uses_the_default(self):
        # Default limiter: 10 req/sec, burst 10; 10 items fit in burst
        assert estimate_duration("not-a-service", 10) == 0.0
