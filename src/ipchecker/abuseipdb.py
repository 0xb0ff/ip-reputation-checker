#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import requests
from ipwhois import IPWhois


@dataclass(frozen=True)
class AbuseIPDBResult:
    ip: str
    score: int
    country: Optional[str]
    isp: Optional[str]
    usage_type: Optional[str]
    domain: Optional[str]
    is_public: Optional[bool]
    total_reports: Optional[int]
    last_reported_at: Optional[str]
    asn: Optional[str]
    raw: dict[str, Any]


class AbuseIPDBClient:
    """AbuseIPDB API v2 client (check endpoint)."""

    def __init__(self, api_key: str, base_url: str = "https://api.abuseipdb.com/api/v2", timeout: int = 10):
        if not api_key:
            raise ValueError("Missing AbuseIPDB API key (ABUSEIPDB_API_KEY).")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self.session = requests.Session()
        self.session.headers.update(
            {
                "Key": self.api_key,
                "Accept": "application/json",
                "User-Agent": "ipchecker/1.0",
            }
        )

    def check_ip(self, ip: str, max_age_days: int = 90, verbose: bool = False) -> AbuseIPDBResult:
        url = f"{self.base_url}/check"
        params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": "true" if verbose else "false"}

        try:
            r = self.session.get(url, params=params, timeout=self.timeout)
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            try:
                payload = r.json()
            except Exception:
                payload = None
            msg = f"HTTP {getattr(r, 'status_code', '?')} - {payload or str(e)}"
            raise RuntimeError(msg) from e
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Network error: {e}") from e

        payload = r.json()
        data = payload.get("data", {}) or {}

        # ASN via RDAP (best-effort)
        asn_str = None
        try:
            whois = IPWhois(ip).lookup_rdap()
            asn_str = f"{whois.get('asn')} - {whois.get('asn_country_code')} - {whois.get('asn_description')}"
        except Exception:
            # Keep ASN empty if lookup fails
            asn_str = None

        return AbuseIPDBResult(
            ip=data.get("ipAddress", ip),
            score=int(data.get("abuseConfidenceScore", 0)),
            country=data.get("countryCode"),
            isp=data.get("isp"),
            usage_type=data.get("usageType"),
            domain=data.get("domain"),
            is_public=data.get("isPublic"),
            total_reports=data.get("totalReports"),
            last_reported_at=data.get("lastReportedAt"),
            asn=asn_str,
            raw=data,
        )
