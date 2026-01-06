#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from typing import Optional

from .abuseipdb import AbuseIPDBClient, AbuseIPDBResult
from .verdict import vt_verdict
from .vt_client import VirusTotalIPClient, VTIPReputation


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check IP reputation using AbuseIPDB (API v2) and VirusTotal (API v3)."
    )
    p.add_argument("ip", help="IP address to check (e.g., 8.8.8.8)")
    p.add_argument(
        "--max-age", type=int, default=90, help="Maximum report age (days) [default: 90]"
    )
    p.add_argument("--verbose", action="store_true", help="Include more details from the API")
    p.add_argument("--json", action="store_true", help="Raw JSON output (data)")
    p.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds [default: 10]")
    p.add_argument(
        "--abuseip-api-key",
        default=os.getenv("ABUSEIPDB_API_KEY"),
        help="AbuseIP API key (otherwise use env ABUSEIPDB_API_KEY)",
    )
    p.add_argument(
        "--virustotal-api-key",
        default=os.getenv("VIRUSTOTAL_API_KEY"),
        help="VirusTotal API key (otherwise use env VIRUSTOTAL_API_KEY)",
    )
    return p


def print_human(abu: AbuseIPDBResult, vt: Optional[VTIPReputation]) -> None:
    print("########## AbuseIPDB ##########\r\n")
    print(f"\tIP:            {abu.ip}")
    print(f"\tASN:           {abu.asn or '-'}")
    print(f"\tScore:         {abu.score}/100")
    print(f"\tCountry:       {abu.country or '-'}")
    print(f"\tISP:           {abu.isp or '-'}")
    print(f"\tUsage type:    {abu.usage_type or '-'}")
    print(f"\tDomain:        {abu.domain or '-'}")
    print(f"\tPublic:        {abu.is_public if abu.is_public is not None else '-'}")
    print(f"\tTotal reports: {abu.total_reports if abu.total_reports is not None else '-'}")
    print(f"\tLast reported: {abu.last_reported_at or '-'}")

    print("\r\n########## VirusTotals ##########\r\n")
    if vt is None:
        print("\tVirusTotal:    unavailable")
        return

    print(f"\tMalicious:     {vt.malicious}")
    print(f"\tSuspicious:    {vt.suspicious}")
    print(f"\tHarmless:      {vt.harmless}")
    print(f"\tTimeout:       {vt.timeout}")
    print(f"\tUndetected:    {vt.undetected}")

    # Simple AbuseIPDB verdict
    if abu.score >= 75:
        ipr_verdict = "HIGH RISK"
    elif abu.score >= 25:
        ipr_verdict = "MEDIUM RISK"
    else:
        ipr_verdict = "LOW RISK"

    print(f"\r\nIP Reputation:                {ipr_verdict}")

    vt = vt_verdict(
        malicious=vt.malicious,
        suspicious=vt.suspicious,
        harmless=vt.harmless,
        undetected=vt.undetected,
        timeout=vt.timeout,
    )
    print(
        f"\rVirusTotal Verdict:           {vt.verdict} (confidence={vt.confidence}, score={vt.score})"
    )
    print(f"\rVT Reason:                    {vt.reason}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        print("Error: invalid IP address.", file=sys.stderr)
        return 2

    if not args.abuseip_api_key:
        print(
            "Error: missing AbuseIPDB API key. Set ABUSEIPDB_API_KEY or use --abuseip-api-key.",
            file=sys.stderr,
        )
        return 2

    if not args.virustotal_api_key:
        print(
            "Error: missing VirusTotal API key. Set VIRUSTOTAL_API_KEY or use --virustotal-api-key.",
            file=sys.stderr,
        )
        return 2

    try:
        abuse = AbuseIPDBClient(api_key=args.abuseip_api_key, timeout=args.timeout)
        abu_res = abuse.check_ip(args.ip, max_age_days=args.max_age, verbose=args.verbose)

        vt_client = VirusTotalIPClient(
            api_key=args.virustotal_api_key, timeout=max(1, args.timeout)
        )
        vt_res = vt_client.check_ip(args.ip)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(
            json.dumps(
                {"abuseipdb": abu_res.raw, "virustotal": vt_res.raw}, indent=2, ensure_ascii=False
            )
        )
    else:
        print_human(abu_res, vt_res)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
