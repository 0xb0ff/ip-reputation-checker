from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import vt  # pip install vt-py


@dataclass(frozen=True)
class VTIPReputation:
    ip: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    timeout: int 
    raw: dict[str, Any]


class VirusTotalIPClient:
    """VirusTotal API v3 client for IP reputation (via vt-py)."""

    def __init__(self, api_key: str, timeout: int = 15):
        if not api_key:
            raise ValueError("Missing VirusTotal API key (VIRUSTOTAL_API_KEY).")
        self.api_key = api_key
        self.timeout = timeout

    def check_ip(self, ip: str) -> VTIPReputation:
        with vt.Client(self.api_key, timeout=self.timeout) as client:
            obj = client.get_object(f"/ip_addresses/{ip}")

        # obj est un objet vt-py; on récupère attributes
        stats = obj.last_analysis_stats

        return VTIPReputation(
            ip=ip,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            timeout=int(stats.get("timeout", 0)),
            raw=stats,
        )