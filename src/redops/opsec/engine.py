from redops.models.engagement import OpsecCheckResult, OpsecResult, OpsecGrade
from redops.opsec.checks import (
    check_domain_age, check_vt_reputation, check_ct_exposure,
    check_ssl_validity, check_spf, check_dkim, check_dmarc,
    check_http_redirect, check_open_ports,
)


# Points per passing check (9 checks × 11 = 99 → normalize to 100)
POINTS_PER_CHECK = 11
TOTAL_CHECKS = 9


def _grade(score: int) -> OpsecGrade:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def _compute_score(checks: list[OpsecCheckResult]) -> int:
    """Score based on non-skip checks. Skip = 0 pts but doesn't penalize."""
    pts = sum(POINTS_PER_CHECK for c in checks if c.status == "pass")
    # Normalize: if all non-skip checks pass, score = 100
    non_skip = [c for c in checks if c.status != "skip"]
    if not non_skip:
        return 100  # all skipped = can't evaluate = neutral 100
    max_pts = len(non_skip) * POINTS_PER_CHECK
    return min(100, round(pts * 100 / max_pts)) if max_pts > 0 else 100


class OpsecEngine:
    def __init__(self, vt_key: str | None = None):
        self._vt_key = vt_key

    async def run(self, domain: str) -> OpsecResult:
        import asyncio
        checks = await asyncio.gather(
            check_domain_age(domain),
            check_vt_reputation(domain, vt_key=self._vt_key),
            check_ct_exposure(domain),
            check_ssl_validity(domain),
            check_spf(domain),
            check_dkim(domain),
            check_dmarc(domain),
            check_http_redirect(domain),
            check_open_ports(domain),
        )
        checks = list(checks)
        score = _compute_score(checks)
        grade = _grade(score)
        return OpsecResult(domain=domain, checks=checks, score=score, grade=grade)
