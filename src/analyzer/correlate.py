from dataclasses import dataclass
from typing import List, Dict, Optional

from .dast import DASTFinding
from .sast import SASTFinding
from .dump_audit import DumpFinding


@dataclass
class CorrelatedRisk:
    severity: str
    score: int
    reason: str
    dast: List[DASTFinding]
    sast: List[SASTFinding]
    dump: List[DumpFinding]


SEVERITY_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 70,
    "MEDIUM": 40,
    "LOW": 20,
    "INFO": 5,
}


def _max_severity(severities: List[str]) -> str:
    if not severities:
        return "INFO"
    return sorted(severities, key=lambda s: SEVERITY_WEIGHTS.get(s, 0), reverse=True)[0]


def correlate(dast: List[DASTFinding], sast: List[SASTFinding], dump: List[DumpFinding]) -> CorrelatedRisk:
    # Link DAST param to SAST findings mentioning the same param
    params = {f.param for f in dast if f.param}
    linked_sast = [s for s in sast if s.param and s.param in params]
    # Also include SAST SQL construction findings (HIGH) even if not parameter matched
    linked_sast += [s for s in sast if "SQL query built" in s.issue]

    # Risk score heuristic:
    # Base = max severity weight across all findings
    # Bonus: +30 if DAST and SAST both present for same parameter; +20 if dump has critical formats
    severities = [
        *["CRITICAL" if f.technique == "time" else "HIGH" for f in dast],
        *[f.severity for f in linked_sast],
        *[f.severity for f in dump],
    ]
    base = SEVERITY_WEIGHTS.get(_max_severity(severities), 0)
    bonus = 0
    if dast and linked_sast:
        bonus += 30
    if any(d.severity in ("CRITICAL", "HIGH") for d in dump):
        bonus += 20
    score = min(100, base + bonus)

    reason = ""
    if dast:
        reason += f"DAST found {len(dast)} potential SQLi vectors. "
    if linked_sast:
        reason += f"SAST found {len(linked_sast)} insecure patterns linked to parameters. "
    if dump:
        reason += f"Dump shows {len(dump)} password hashes with varying strengths."

    return CorrelatedRisk(
        severity=_max_severity(severities),
        score=score,
        reason=reason.strip(),
        dast=dast,
        sast=linked_sast,
        dump=dump,
    )