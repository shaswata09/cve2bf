"""Fetches and normalises CVE records from the NVD 2.0 REST API.

Responsibilities:

* call ``GET /rest/json/cves/2.0?cveId=...`` (with optional API key);
* extract the fields the pipeline needs: English description, CVSS base score
  and severity, CWE ids, vendor/product and references;
* serve a bundled offline fixture for well-known CVEs so the platform works in
  air-gapped environments and so tests are deterministic.

Network and parsing failures raise :class:`NVDError`; the caller decides how to
surface them.
"""
from __future__ import annotations

import logging

import httpx

from app.config import Settings
from app.models.api_schemas import CVEMetadata

logger = logging.getLogger(__name__)


class NVDError(RuntimeError):
    """Raised when a CVE cannot be fetched or parsed."""


class CVENotFoundError(NVDError):
    """Raised when NVD returns no record for the requested CVE id."""


#: Offline fixtures keyed by CVE id. Enough to demo the full pipeline without a
#: network connection. Values mirror the shape returned by ``_parse``.
_FIXTURES: dict[str, dict] = {
    "CVE-2014-0160": {
        "description": (
            "Missing verification of 'payload' towards an upper limit leads to the use of an "
            "inconsistent size for an object, allowing a pointer to reposition over its bounds, "
            "which when used in 'memcpy()' leads to a heap buffer over-read. If exploited, this "
            "can lead to exposure of sensitive information (IEX) - confidentiality loss."
        ),
        "cvss_score": 7.5,
        "cvss_severity": "HIGH",
        "cwe_ids": ["CWE-125"],
        "vendor_project": "openssl",
        "product": "openssl",
        "references": [
            "https://www.seancassidy.me/diagnosis-of-the-openssl-heartbleed-bug.html",
            "https://github.com/openssl/openssl/commit/96db9023b881d7cd9f379b0c154650d6c108e9a3",
        ],
    }
}


class NVDClient:
    """Client for the NVD 2.0 CVE API with offline fixture support."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._base_url = settings.nvd_base_url
        self._api_key = settings.nvd_api_key
        self._timeout = settings.nvd_timeout_seconds

    def fetch(self, cve_id: str) -> CVEMetadata:
        """Return :class:`CVEMetadata` for ``cve_id``.

        Offline mode (or a matching fixture in offline mode) is served locally.
        Otherwise NVD is queried; a fixture is used as a last-resort fallback if
        the network call fails.
        """
        cve_id = cve_id.strip().upper()

        if self._settings.offline_mode:
            return self._from_fixture(cve_id)

        try:
            return self._fetch_remote(cve_id)
        except CVENotFoundError:
            raise
        except NVDError:
            if cve_id in _FIXTURES:
                logger.warning("NVD fetch failed for %s; serving offline fixture.", cve_id)
                return self._from_fixture(cve_id)
            raise

    # -- remote -------------------------------------------------------------
    def _fetch_remote(self, cve_id: str) -> CVEMetadata:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        try:
            resp = httpx.get(
                self._base_url,
                params={"cveId": cve_id},
                headers=headers,
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise NVDError(f"NVD request failed for {cve_id}: {exc}") from exc

        body = resp.json()
        vulns = body.get("vulnerabilities", [])
        if not vulns:
            raise CVENotFoundError(f"No NVD record for {cve_id}.")
        return self._parse(cve_id, vulns[0]["cve"])

    def _parse(self, cve_id: str, cve: dict) -> CVEMetadata:
        """Normalise a raw NVD ``cve`` object into :class:`CVEMetadata`."""
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        score, severity = self._parse_cvss(cve.get("metrics", {}))
        cwe_ids = self._parse_cwes(cve.get("weaknesses", []))
        references = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

        return CVEMetadata(
            cve_id=cve_id,
            description=description,
            cvss_score=score,
            cvss_severity=severity,
            cwe_ids=cwe_ids,
            references=references[:10],
            from_fixture=False,
        )

    @staticmethod
    def _parse_cvss(metrics: dict) -> tuple[float | None, str | None]:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0].get("cvssData", {})
                score = data.get("baseScore")
                severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
                return score, severity
        return None, None

    @staticmethod
    def _parse_cwes(weaknesses: list) -> list[str]:
        cwes: list[str] = []
        for w in weaknesses:
            for desc in w.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-") and value not in cwes:
                    cwes.append(value)
        return cwes

    # -- fixtures -----------------------------------------------------------
    def _from_fixture(self, cve_id: str) -> CVEMetadata:
        fixture = _FIXTURES.get(cve_id)
        if fixture is None:
            raise CVENotFoundError(
                f"{cve_id} is not available offline. Disable offline_mode or add a fixture."
            )
        return CVEMetadata(cve_id=cve_id, from_fixture=True, **fixture)
