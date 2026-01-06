from dataclasses import dataclass


@dataclass(frozen=True)
class VTVerdict:
    verdict: str  # LOW_RISK / MEDIUM_RISK / HIGH_RISK / INSUFFICIENT_DATA
    confidence: str  # LOW / MEDIUM / HIGH
    score: int  # 0..100 (indicative)
    reason: str


def vt_verdict(
    malicious: int, suspicious: int, harmless: int, undetected: int, timeout: int
) -> VTVerdict:
    m = max(0, int(malicious))
    s = max(0, int(suspicious))
    h = max(0, int(harmless))
    u = max(0, int(undetected))
    t = max(0, int(timeout))

    bad = m + s
    good = h + u
    total = bad + good + t

    if total < 5:
        return VTVerdict(
            verdict="INSUFFICIENT_DATA",
            confidence="LOW",
            score=50,
            reason=f"Too few VT votes (total={total}).",
        )

    bad_ratio = bad / total
    timeout_ratio = t / total

    risk_points = (m * 12) + (s * 7) + (t * 2)
    denom = max(1, (good * 4) + (bad * 6) + (t * 2))
    score = max(0, min(100, int(100 * risk_points / denom)))

    if m >= 3 or bad >= 5 or bad_ratio >= 0.30:
        conf = "HIGH" if total >= 10 else "MEDIUM"
        return VTVerdict(
            verdict="HIGH_RISK",
            confidence=conf,
            score=max(score, 75),
            reason=f"Bad votes are significant (malicious={m}, suspicious={s}, bad_ratio={bad_ratio:.0%}, total={total}).",
        )

    if bad > 0 or timeout_ratio >= 0.30:
        conf = "MEDIUM" if total >= 10 else "LOW"
        why = []
        if bad > 0:
            why.append(f"some bad votes (malicious={m}, suspicious={s})")
        if timeout_ratio >= 0.30:
            why.append(f"high timeout ratio ({timeout_ratio:.0%})")
        return VTVerdict(
            verdict="MEDIUM_RISK",
            confidence=conf,
            score=max(score, 40),
            reason="; ".join(why) + f" (total={total}).",
        )

    if bad == 0 and good >= 5:
        conf = "HIGH" if total >= 10 else "MEDIUM"
        return VTVerdict(
            verdict="LOW_RISK",
            confidence=conf,
            score=min(score, 25),
            reason=f"No bad votes and good coverage (harmless={h}, undetected={u}, total={total}).",
        )

    return VTVerdict(
        verdict="MEDIUM_RISK",
        confidence="LOW",
        score=max(score, 40),
        reason=f"Unclear VT consensus (malicious={m}, suspicious={s}, harmless={h}, undetected={u}, timeout={t}, total={total}).",
    )
