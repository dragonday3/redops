"""Tests for the OPSEC Validation Engine — Task 2."""
from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from redops.models.engagement import OpsecCheckResult, OpsecResult
from redops.opsec.checks import (
    check_ct_exposure,
    check_dkim,
    check_dmarc,
    check_domain_age,
    check_http_redirect,
    check_open_ports,
    check_spf,
    check_ssl_validity,
    check_vt_reputation,
)
from redops.opsec.engine import OpsecEngine, _compute_score, _grade


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_dns_answer(txt: str):
    """Create a mock DNS answer record with to_text() returning txt."""
    rec = MagicMock()
    rec.to_text.return_value = txt
    return rec


# ── check_domain_age ───────────────────────────────────────────────────────────

class TestCheckDomainAge:
    @pytest.mark.asyncio
    async def test_old_domain_pass(self):
        """Domain created 200 days ago should pass."""
        creation = datetime.now(timezone.utc) - timedelta(days=200)
        mock_whois = MagicMock()
        mock_whois.creation_date = creation
        with patch("whois.whois", return_value=mock_whois):
            result = await check_domain_age("example.com")
        assert result.status == "pass"
        assert result.name == "domain_age"
        assert "200" in result.detail

    @pytest.mark.asyncio
    async def test_new_domain_warn(self):
        """Domain created 5 days ago should warn."""
        creation = datetime.now(timezone.utc) - timedelta(days=5)
        mock_whois = MagicMock()
        mock_whois.creation_date = creation
        with patch("whois.whois", return_value=mock_whois):
            result = await check_domain_age("newdomain.com")
        assert result.status == "warn"
        assert "5" in result.detail
        assert result.remediation != ""

    @pytest.mark.asyncio
    async def test_whois_exception_skip(self):
        """WHOIS failure should return skip."""
        with patch("whois.whois", side_effect=Exception("connection timeout")):
            result = await check_domain_age("broken.com")
        assert result.status == "skip"
        assert "WHOIS lookup failed" in result.detail

    @pytest.mark.asyncio
    async def test_none_creation_date_skip(self):
        """None creation date from WHOIS should return skip."""
        mock_whois = MagicMock()
        mock_whois.creation_date = None
        with patch("whois.whois", return_value=mock_whois):
            result = await check_domain_age("unknown.com")
        assert result.status == "skip"
        assert "unavailable" in result.detail

    @pytest.mark.asyncio
    async def test_list_creation_date_uses_first(self):
        """List of creation dates should use the first one."""
        old = datetime.now(timezone.utc) - timedelta(days=100)
        mock_whois = MagicMock()
        mock_whois.creation_date = [old, datetime.now(timezone.utc)]
        with patch("whois.whois", return_value=mock_whois):
            result = await check_domain_age("multi.com")
        assert result.status == "pass"


# ── check_vt_reputation ────────────────────────────────────────────────────────

class TestCheckVtReputation:
    @pytest.mark.asyncio
    async def test_no_key_skip(self):
        """Missing API key should skip."""
        result = await check_vt_reputation("example.com", vt_key=None)
        assert result.status == "skip"
        assert "No VirusTotal API key" in result.detail

    @pytest.mark.asyncio
    @respx.mock
    async def test_404_pass(self):
        """Domain not in VT (404) should pass."""
        respx.get("https://www.virustotal.com/api/v3/domains/clean.com").mock(
            return_value=httpx.Response(404)
        )
        result = await check_vt_reputation("clean.com", vt_key="fakekey")
        assert result.status == "pass"
        assert "not found" in result.detail

    @pytest.mark.asyncio
    @respx.mock
    async def test_zero_detections_pass(self):
        """Zero malicious and suspicious detections should pass."""
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0}
                }
            }
        }
        respx.get("https://www.virustotal.com/api/v3/domains/good.com").mock(
            return_value=httpx.Response(200, json=payload)
        )
        result = await check_vt_reputation("good.com", vt_key="fakekey")
        assert result.status == "pass"

    @pytest.mark.asyncio
    @respx.mock
    async def test_malicious_detections_fail(self):
        """Malicious detections should fail."""
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 3, "suspicious": 1}
                }
            }
        }
        respx.get("https://www.virustotal.com/api/v3/domains/bad.com").mock(
            return_value=httpx.Response(200, json=payload)
        )
        result = await check_vt_reputation("bad.com", vt_key="fakekey")
        assert result.status == "fail"
        assert "3 malicious" in result.detail

    @pytest.mark.asyncio
    @respx.mock
    async def test_suspicious_only_warn(self):
        """Suspicious (no malicious) detections should warn."""
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 2}
                }
            }
        }
        respx.get("https://www.virustotal.com/api/v3/domains/sus.com").mock(
            return_value=httpx.Response(200, json=payload)
        )
        result = await check_vt_reputation("sus.com", vt_key="fakekey")
        assert result.status == "warn"

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200_non_404_skip(self):
        """Non-200/404 HTTP response should skip."""
        respx.get("https://www.virustotal.com/api/v3/domains/err.com").mock(
            return_value=httpx.Response(500)
        )
        result = await check_vt_reputation("err.com", vt_key="fakekey")
        assert result.status == "skip"
        assert "500" in result.detail


# ── check_ct_exposure ──────────────────────────────────────────────────────────

class TestCheckCtExposure:
    @pytest.mark.asyncio
    @respx.mock
    async def test_no_certs_pass(self):
        """No certs in CT logs should pass."""
        respx.get("https://crt.sh/?q=example.com&output=json").mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await check_ct_exposure("example.com")
        assert result.status == "pass"
        assert "No certificates" in result.detail

    @pytest.mark.asyncio
    @respx.mock
    async def test_certs_found_warn(self):
        """Certificates found should warn."""
        certs = [{"name_value": f"sub{i}.example.com"} for i in range(3)]
        respx.get("https://crt.sh/?q=exposed.com&output=json").mock(
            return_value=httpx.Response(200, json=certs)
        )
        result = await check_ct_exposure("exposed.com")
        assert result.status == "warn"
        assert "3" in result.detail
        assert result.remediation != ""

    @pytest.mark.asyncio
    @respx.mock
    async def test_http_error_skip(self):
        """HTTP error from crt.sh should skip."""
        respx.get("https://crt.sh/?q=broken.com&output=json").mock(
            return_value=httpx.Response(503)
        )
        result = await check_ct_exposure("broken.com")
        assert result.status == "skip"
        assert "503" in result.detail


# ── check_ssl_validity ─────────────────────────────────────────────────────────

class TestCheckSslValidity:
    @pytest.mark.asyncio
    async def test_valid_cert_pass(self):
        """Cert with 30 days left should pass."""
        future = datetime.now(timezone.utc) + timedelta(days=30)

        with patch("redops.opsec.checks.asyncio.get_event_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop
            loop.run_in_executor = AsyncMock(return_value=future)
            result = await check_ssl_validity("example.com")

        assert result.status == "pass"
        # Days left is computed at runtime so allow ±1 from rounding
        assert "expires in" in result.detail

    @pytest.mark.asyncio
    async def test_expiring_soon_warn(self):
        """Cert with 7 days left should warn."""
        future = datetime.now(timezone.utc) + timedelta(days=7)

        with patch("redops.opsec.checks.asyncio.get_event_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop
            loop.run_in_executor = AsyncMock(return_value=future)
            result = await check_ssl_validity("expiring.com")

        assert result.status == "warn"
        assert "expires in" in result.detail

    @pytest.mark.asyncio
    async def test_expired_cert_fail(self):
        """Expired cert should fail."""
        past = datetime.now(timezone.utc) - timedelta(days=5)

        with patch("redops.opsec.checks.asyncio.get_event_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop
            loop.run_in_executor = AsyncMock(return_value=past)
            result = await check_ssl_validity("expired.com")

        assert result.status == "fail"
        assert "expired" in result.detail.lower()

    @pytest.mark.asyncio
    async def test_connection_error_skip(self):
        """Connection error should skip."""
        with patch("redops.opsec.checks.asyncio.get_event_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop
            loop.run_in_executor = AsyncMock(side_effect=OSError("connection refused"))
            result = await check_ssl_validity("nohost.com")

        assert result.status == "skip"

    @pytest.mark.asyncio
    async def test_ssl_error_fail(self):
        """SSL error should fail."""
        with patch("redops.opsec.checks.asyncio.get_event_loop") as mock_loop:
            loop = MagicMock()
            mock_loop.return_value = loop
            loop.run_in_executor = AsyncMock(side_effect=ssl.SSLError("cert verify failed"))
            result = await check_ssl_validity("badssl.com")

        assert result.status == "fail"
        assert "SSL error" in result.detail


# ── check_spf ──────────────────────────────────────────────────────────────────

class TestCheckSpf:
    @pytest.mark.asyncio
    async def test_spf_found_pass(self):
        """SPF record present should pass."""
        mock_answers = [_make_dns_answer('"v=spf1 include:sendgrid.net -all"')]
        with patch("dns.asyncresolver.resolve", return_value=mock_answers):
            result = await check_spf("example.com")
        assert result.status == "pass"
        assert "SPF record found" in result.detail

    @pytest.mark.asyncio
    async def test_no_spf_fail(self):
        """No SPF record should fail."""
        mock_answers = [_make_dns_answer('"v=something-else"')]
        with patch("dns.asyncresolver.resolve", return_value=mock_answers):
            result = await check_spf("nospf.com")
        assert result.status == "fail"
        assert result.remediation != ""

    @pytest.mark.asyncio
    async def test_dns_error_skip(self):
        """DNS resolution failure should skip."""
        with patch("dns.asyncresolver.resolve", side_effect=Exception("NXDOMAIN")):
            result = await check_spf("broken.com")
        assert result.status == "skip"
        assert "DNS lookup failed" in result.detail


# ── check_dkim ─────────────────────────────────────────────────────────────────

class TestCheckDkim:
    @pytest.mark.asyncio
    async def test_dkim_found_pass(self):
        """DKIM record present should pass."""
        mock_answers = [_make_dns_answer('"v=DKIM1; k=rsa; p=MIGfMA..."')]
        with patch("dns.asyncresolver.resolve", return_value=mock_answers):
            result = await check_dkim("example.com")
        assert result.status == "pass"
        assert "default._domainkey.example.com" in result.detail

    @pytest.mark.asyncio
    async def test_no_dkim_fail(self):
        """Missing DKIM record should fail."""
        with patch("dns.asyncresolver.resolve", side_effect=Exception("NXDOMAIN")):
            result = await check_dkim("nodkim.com")
        assert result.status == "fail"
        assert "default._domainkey.nodkim.com" in result.detail
        assert result.remediation != ""


# ── check_dmarc ────────────────────────────────────────────────────────────────

class TestCheckDmarc:
    @pytest.mark.asyncio
    async def test_dmarc_reject_pass(self):
        """DMARC with p=reject should pass."""
        mock_answers = [_make_dns_answer('"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"')]
        with patch("dns.asyncresolver.resolve", return_value=mock_answers):
            result = await check_dmarc("example.com")
        assert result.status == "pass"

    @pytest.mark.asyncio
    async def test_dmarc_quarantine_pass(self):
        """DMARC with p=quarantine should pass."""
        mock_answers = [_make_dns_answer('"v=DMARC1; p=quarantine;"')]
        with patch("dns.asyncresolver.resolve", return_value=mock_answers):
            result = await check_dmarc("example.com")
        assert result.status == "pass"

    @pytest.mark.asyncio
    async def test_dmarc_none_warn(self):
        """DMARC with p=none should warn."""
        mock_answers = [_make_dns_answer('"v=DMARC1; p=none;"')]
        with patch("dns.asyncresolver.resolve", return_value=mock_answers):
            result = await check_dmarc("weak.com")
        assert result.status == "warn"
        assert "none" in result.detail

    @pytest.mark.asyncio
    async def test_no_dmarc_fail(self):
        """Missing DMARC record should fail."""
        with patch("dns.asyncresolver.resolve", side_effect=Exception("NXDOMAIN")):
            result = await check_dmarc("nodmarc.com")
        assert result.status == "fail"
        assert result.remediation != ""


# ── check_http_redirect ────────────────────────────────────────────────────────

class TestCheckHttpRedirect:
    @pytest.mark.asyncio
    @respx.mock
    async def test_200_pass(self):
        """HTTP 200 response should pass."""
        respx.head("http://example.com").mock(return_value=httpx.Response(200))
        result = await check_http_redirect("example.com")
        assert result.status == "pass"
        assert "200" in result.detail

    @pytest.mark.asyncio
    @respx.mock
    async def test_500_fail(self):
        """HTTP 500 response should fail."""
        respx.head("http://example.com").mock(return_value=httpx.Response(500))
        result = await check_http_redirect("example.com")
        assert result.status == "fail"
        assert "500" in result.detail

    @pytest.mark.asyncio
    async def test_connect_error_warn(self):
        """ConnectError should warn (HTTPS-only host)."""
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.head = AsyncMock(side_effect=httpx.ConnectError("refused"))
            result = await check_http_redirect("httpsonly.com")
        assert result.status == "warn"


# ── check_open_ports ───────────────────────────────────────────────────────────

class TestCheckOpenPorts:
    @pytest.mark.asyncio
    async def test_only_expected_ports_pass(self):
        """Only 80 and 443 open (the defaults) should pass."""
        async def _fake_probe(host, port):
            if port in (80, 443):
                return port
            raise OSError("refused")

        with patch("asyncio.open_connection", side_effect=_fake_probe):
            result = await check_open_ports("example.com", expected_ports={80, 443})
        assert result.status == "pass"
        assert "No unexpected ports" in result.detail

    @pytest.mark.asyncio
    async def test_unexpected_port_warn(self):
        """Unexpected open port (e.g., 4444) should warn."""
        async def _fake_probe(host, port):
            if port in (80, 443, 4444):
                # Return a mock writer
                writer = MagicMock()
                writer.close = MagicMock()
                return MagicMock(), writer
            raise OSError("refused")

        with patch("asyncio.open_connection", side_effect=_fake_probe):
            result = await check_open_ports("c2.com", expected_ports={80, 443})
        assert result.status == "warn"
        assert "4444" in result.detail
        assert result.remediation != ""


# ── _compute_score ─────────────────────────────────────────────────────────────

class TestComputeScore:
    def _make_checks(self, statuses: list[str]) -> list[OpsecCheckResult]:
        return [OpsecCheckResult(name=f"check_{i}", status=s) for i, s in enumerate(statuses)]

    def test_all_pass_100(self):
        checks = self._make_checks(["pass"] * 9)
        assert _compute_score(checks) == 100

    def test_all_fail_0(self):
        checks = self._make_checks(["fail"] * 9)
        assert _compute_score(checks) == 0

    def test_all_skip_100(self):
        checks = self._make_checks(["skip"] * 9)
        assert _compute_score(checks) == 100

    def test_mixed_score(self):
        # 5 pass, 4 fail → 5/9 ≈ 56
        checks = self._make_checks(["pass"] * 5 + ["fail"] * 4)
        score = _compute_score(checks)
        assert 50 <= score <= 60

    def test_skip_does_not_penalize(self):
        # 5 pass, 4 skip → should score 100 (5/5 non-skip pass)
        checks = self._make_checks(["pass"] * 5 + ["skip"] * 4)
        assert _compute_score(checks) == 100

    def test_warn_counts_as_non_pass(self):
        # 5 pass, 4 warn → 5/9 ≈ 56
        checks = self._make_checks(["pass"] * 5 + ["warn"] * 4)
        score = _compute_score(checks)
        assert 50 <= score <= 60


# ── _grade ─────────────────────────────────────────────────────────────────────

class TestGrade:
    def test_a_threshold(self):
        assert _grade(90) == "A"
        assert _grade(100) == "A"

    def test_b_threshold(self):
        assert _grade(75) == "B"
        assert _grade(89) == "B"

    def test_c_threshold(self):
        assert _grade(60) == "C"
        assert _grade(74) == "C"

    def test_d_threshold(self):
        assert _grade(45) == "D"
        assert _grade(59) == "D"

    def test_f_threshold(self):
        assert _grade(0) == "F"
        assert _grade(44) == "F"


# ── OpsecEngine.run ────────────────────────────────────────────────────────────

class TestOpsecEngineRun:
    @pytest.mark.asyncio
    async def test_run_returns_opsec_result(self):
        """Full engine run with all checks mocked returns OpsecResult."""
        pass_result = OpsecCheckResult(name="test", status="pass")
        skip_result = OpsecCheckResult(name="test", status="skip")

        all_pass = [pass_result] * 9

        with (
            patch("redops.opsec.engine.check_domain_age", return_value=pass_result),
            patch("redops.opsec.engine.check_vt_reputation", return_value=skip_result),
            patch("redops.opsec.engine.check_ct_exposure", return_value=pass_result),
            patch("redops.opsec.engine.check_ssl_validity", return_value=pass_result),
            patch("redops.opsec.engine.check_spf", return_value=pass_result),
            patch("redops.opsec.engine.check_dkim", return_value=pass_result),
            patch("redops.opsec.engine.check_dmarc", return_value=pass_result),
            patch("redops.opsec.engine.check_http_redirect", return_value=pass_result),
            patch("redops.opsec.engine.check_open_ports", return_value=pass_result),
        ):
            engine = OpsecEngine(vt_key=None)
            result = await engine.run("example.com")

        assert isinstance(result, OpsecResult)
        assert result.domain == "example.com"
        assert len(result.checks) == 9
        assert result.score > 0
        assert result.grade in ("A", "B", "C", "D", "F")

    @pytest.mark.asyncio
    async def test_run_grade_a_when_all_pass(self):
        """All-pass engine run yields grade A."""
        pass_result = OpsecCheckResult(name="test", status="pass")

        with (
            patch("redops.opsec.engine.check_domain_age", return_value=pass_result),
            patch("redops.opsec.engine.check_vt_reputation", return_value=pass_result),
            patch("redops.opsec.engine.check_ct_exposure", return_value=pass_result),
            patch("redops.opsec.engine.check_ssl_validity", return_value=pass_result),
            patch("redops.opsec.engine.check_spf", return_value=pass_result),
            patch("redops.opsec.engine.check_dkim", return_value=pass_result),
            patch("redops.opsec.engine.check_dmarc", return_value=pass_result),
            patch("redops.opsec.engine.check_http_redirect", return_value=pass_result),
            patch("redops.opsec.engine.check_open_ports", return_value=pass_result),
        ):
            engine = OpsecEngine()
            result = await engine.run("perfect.com")

        assert result.grade == "A"
        assert result.score == 100

    @pytest.mark.asyncio
    async def test_run_grade_f_when_all_fail(self):
        """All-fail engine run yields grade F."""
        fail_result = OpsecCheckResult(name="test", status="fail")

        with (
            patch("redops.opsec.engine.check_domain_age", return_value=fail_result),
            patch("redops.opsec.engine.check_vt_reputation", return_value=fail_result),
            patch("redops.opsec.engine.check_ct_exposure", return_value=fail_result),
            patch("redops.opsec.engine.check_ssl_validity", return_value=fail_result),
            patch("redops.opsec.engine.check_spf", return_value=fail_result),
            patch("redops.opsec.engine.check_dkim", return_value=fail_result),
            patch("redops.opsec.engine.check_dmarc", return_value=fail_result),
            patch("redops.opsec.engine.check_http_redirect", return_value=fail_result),
            patch("redops.opsec.engine.check_open_ports", return_value=fail_result),
        ):
            engine = OpsecEngine()
            result = await engine.run("terrible.com")

        assert result.grade == "F"
        assert result.score == 0
