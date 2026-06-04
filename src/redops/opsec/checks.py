import asyncio
import ssl
import socket
from datetime import datetime, timezone, timedelta

import httpx
import dns.asyncresolver

from redops.models.engagement import OpsecCheckResult


async def check_domain_age(domain: str) -> OpsecCheckResult:
    """Domain should be >30 days old (avoids brand-new burner domains being flagged)."""
    try:
        import whois  # python-whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return OpsecCheckResult(
                name="domain_age",
                status="skip",
                detail="WHOIS creation date unavailable",
                remediation="",
            )
        if isinstance(creation, datetime):
            age = datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc) if creation.tzinfo is None else datetime.now(timezone.utc) - creation
        else:
            # date object
            age = datetime.now(timezone.utc).date() - creation
            age = timedelta(days=age.days)
        if age.days >= 30:
            return OpsecCheckResult(name="domain_age", status="pass", detail=f"Domain age: {age.days} days")
        return OpsecCheckResult(
            name="domain_age", status="warn",
            detail=f"Domain only {age.days} days old — may trigger reputation filters",
            remediation="Age domain for at least 30 days before engagement",
        )
    except Exception as e:
        return OpsecCheckResult(name="domain_age", status="skip", detail=f"WHOIS lookup failed: {e}")


async def check_vt_reputation(domain: str, vt_key: str | None = None) -> OpsecCheckResult:
    """VirusTotal domain reputation — skip if no API key."""
    if not vt_key:
        return OpsecCheckResult(name="vt_reputation", status="skip", detail="No VirusTotal API key provided")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": vt_key},
            )
        if resp.status_code == 404:
            return OpsecCheckResult(name="vt_reputation", status="pass", detail="Domain not found in VirusTotal (clean)")
        if resp.status_code != 200:
            return OpsecCheckResult(name="vt_reputation", status="skip", detail=f"VT API returned {resp.status_code}")
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if malicious == 0 and suspicious == 0:
            return OpsecCheckResult(name="vt_reputation", status="pass", detail=f"0 malicious, 0 suspicious detections")
        status = "fail" if malicious > 0 else "warn"
        return OpsecCheckResult(
            name="vt_reputation", status=status,
            detail=f"{malicious} malicious, {suspicious} suspicious detections",
            remediation="Use a different domain or request VT re-analysis after cleanup",
        )
    except Exception as e:
        return OpsecCheckResult(name="vt_reputation", status="skip", detail=f"VT check failed: {e}")


async def check_ct_exposure(domain: str) -> OpsecCheckResult:
    """Check crt.sh for existing certificates — informs operator of CT log exposure."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"https://crt.sh/?q={domain}&output=json")
        if resp.status_code != 200:
            return OpsecCheckResult(name="ct_exposure", status="skip", detail=f"crt.sh returned {resp.status_code}")
        entries = resp.json()
        count = len(entries)
        names = list({e.get("name_value", "") for e in entries[:10]})
        detail = f"{count} certificate(s) found in CT logs. Sample names: {', '.join(names[:5])}" if count else "No certificates found in CT logs"
        # This is informational — not pass/fail, operator decides
        status = "warn" if count > 0 else "pass"
        remediation = "Review CT log entries — any C2 domains already indexed are known to defenders" if count > 0 else ""
        return OpsecCheckResult(name="ct_exposure", status=status, detail=detail, remediation=remediation)
    except Exception as e:
        return OpsecCheckResult(name="ct_exposure", status="skip", detail=f"CT check failed: {e}")


async def check_ssl_validity(domain: str, port: int = 443) -> OpsecCheckResult:
    """SSL cert must be valid and have >=14 days until expiry."""
    try:
        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _check():
            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expires_str = cert["notAfter"]
                    expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    return expires

        expires = await loop.run_in_executor(None, _check)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 0:
            return OpsecCheckResult(
                name="ssl_validity", status="fail",
                detail=f"Certificate expired {abs(days_left)} days ago",
                remediation="Renew the SSL certificate immediately",
            )
        if days_left < 14:
            return OpsecCheckResult(
                name="ssl_validity", status="warn",
                detail=f"Certificate expires in {days_left} days",
                remediation="Renew certificate before engagement starts",
            )
        return OpsecCheckResult(name="ssl_validity", status="pass", detail=f"Certificate valid, expires in {days_left} days")
    except ssl.SSLError as e:
        return OpsecCheckResult(name="ssl_validity", status="fail", detail=f"SSL error: {e}", remediation="Fix SSL certificate configuration")
    except Exception as e:
        return OpsecCheckResult(name="ssl_validity", status="skip", detail=f"SSL check failed: {e}")


async def check_spf(domain: str) -> OpsecCheckResult:
    """SPF DNS TXT record must exist."""
    try:
        answers = await dns.asyncresolver.resolve(domain, "TXT")
        spf_records = [r.to_text() for r in answers if "v=spf1" in r.to_text()]
        if spf_records:
            return OpsecCheckResult(name="spf_record", status="pass", detail=f"SPF record found: {spf_records[0][:80]}")
        return OpsecCheckResult(
            name="spf_record", status="fail",
            detail="No SPF record found",
            remediation="Add SPF TXT record: v=spf1 include:... -all",
        )
    except Exception as e:
        return OpsecCheckResult(name="spf_record", status="skip", detail=f"DNS lookup failed: {e}")


async def check_dkim(domain: str, selector: str = "default") -> OpsecCheckResult:
    """DKIM TXT record must exist at default._domainkey.{domain}."""
    dkim_domain = f"{selector}._domainkey.{domain}"
    try:
        answers = await dns.asyncresolver.resolve(dkim_domain, "TXT")
        records = [r.to_text() for r in answers]
        if records:
            return OpsecCheckResult(name="dkim_record", status="pass", detail=f"DKIM record found at {dkim_domain}")
        return OpsecCheckResult(name="dkim_record", status="fail", detail=f"No DKIM record at {dkim_domain}", remediation=f"Add DKIM TXT record at {dkim_domain}")
    except Exception as e:
        return OpsecCheckResult(name="dkim_record", status="fail", detail=f"No DKIM record at {dkim_domain}: {e}", remediation=f"Add DKIM TXT record at {dkim_domain}")


async def check_dmarc(domain: str) -> OpsecCheckResult:
    """DMARC TXT record must exist at _dmarc.{domain} with enforce policy."""
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = await dns.asyncresolver.resolve(dmarc_domain, "TXT")
        records = [r.to_text() for r in answers if "v=DMARC1" in r.to_text()]
        if not records:
            return OpsecCheckResult(
                name="dmarc_record", status="fail",
                detail=f"No DMARC record at {dmarc_domain}",
                remediation=f"Add DMARC TXT record: v=DMARC1; p=reject; rua=mailto:...",
            )
        record = records[0]
        if "p=reject" in record or "p=quarantine" in record:
            return OpsecCheckResult(name="dmarc_record", status="pass", detail=f"DMARC record with enforce policy found")
        return OpsecCheckResult(
            name="dmarc_record", status="warn",
            detail=f"DMARC record found but policy is 'none' (monitor only)",
            remediation="Set p=quarantine or p=reject for full enforcement",
        )
    except Exception as e:
        return OpsecCheckResult(
            name="dmarc_record", status="fail",
            detail=f"No DMARC record at {dmarc_domain}: {e}",
            remediation="Add DMARC TXT record",
        )


async def check_http_redirect(domain: str) -> OpsecCheckResult:
    """HTTP redirector chain must resolve successfully (no 5xx errors)."""
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.head(f"http://{domain}")
        if resp.status_code < 500:
            return OpsecCheckResult(
                name="http_redirect", status="pass",
                detail=f"HTTP chain resolved to {resp.status_code} after {len(resp.history)} redirect(s)",
            )
        return OpsecCheckResult(
            name="http_redirect", status="fail",
            detail=f"HTTP chain ended with {resp.status_code}",
            remediation="Fix redirector configuration — server error on health check",
        )
    except httpx.ConnectError:
        return OpsecCheckResult(name="http_redirect", status="warn", detail="HTTP port not responding (domain may be HTTPS-only)", remediation="Ensure redirector is listening on port 80")
    except Exception as e:
        return OpsecCheckResult(name="http_redirect", status="skip", detail=f"HTTP check failed: {e}")


async def check_open_ports(domain: str, expected_ports: set[int] | None = None) -> OpsecCheckResult:
    """Check common ports — warn on unexpected open ports."""
    if expected_ports is None:
        expected_ports = {80, 443}
    probed = [80, 443, 8080, 8443, 22, 3389, 4444, 5555, 8888]
    open_ports: list[int] = []

    async def _probe(port: int) -> int | None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port), timeout=2
            )
            writer.close()
            return port
        except Exception:
            return None

    results = await asyncio.gather(*[_probe(p) for p in probed])
    open_ports = [p for p in results if p is not None]
    unexpected = [p for p in open_ports if p not in expected_ports]
    if not unexpected:
        return OpsecCheckResult(
            name="open_ports", status="pass",
            detail=f"Open ports: {open_ports}. No unexpected ports.",
        )
    return OpsecCheckResult(
        name="open_ports", status="warn",
        detail=f"Unexpected open ports detected: {unexpected}",
        remediation=f"Close or firewall ports {unexpected} before engagement",
    )
