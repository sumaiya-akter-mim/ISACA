import time
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests


SQLI_TIME_PAYLOADS = [
    "SLEEP(3)",  # MySQL
    "pg_sleep(3)",  # PostgreSQL
    "WAITFOR DELAY '0:0:3'",  # SQL Server
]

SQLI_ERROR_PAYLOADS = [
    "'",  # break quotes
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
]


@dataclass
class DASTFinding:
    url: str
    param: str
    technique: str  # "error" or "time"
    response_code: int
    response_time_ms: int
    evidence: str


def _inject_params(url: str, base_params: Dict[str, str], payload: str) -> str:
    params = base_params.copy()
    for k in params.keys():
        params[k] = f"{params[k]}{payload}"
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.urlencode(params)
    rebuilt = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment)
    )
    return rebuilt


def _parse_params(url: str) -> Dict[str, str]:
    parsed = urllib.parse.urlparse(url)
    return dict(urllib.parse.parse_qsl(parsed.query))


def scan_sql_injection(urls: List[str], timeout: float = 5.0) -> List[DASTFinding]:
    findings: List[DASTFinding] = []
    for url in urls:
        base_params = _parse_params(url)
        if not base_params:
            # Attempt to fuzz a single common parameter name if none provided
            base_params = {"q": "test"}
            url = _inject_params(url, base_params, "")

        # Error-based
        for payload in SQLI_ERROR_PAYLOADS:
            test_url = _inject_params(url, base_params, payload)
            start = time.time()
            try:
                resp = requests.get(test_url, timeout=timeout)
                elapsed_ms = int((time.time() - start) * 1000)
                evidence = ""
                if resp.status_code >= 500:
                    evidence = f"HTTP {resp.status_code} on error payload"
                    for p in base_params.keys():
                        findings.append(
                            DASTFinding(
                                url=test_url,
                                param=p,
                                technique="error",
                                response_code=resp.status_code,
                                response_time_ms=elapsed_ms,
                                evidence=evidence,
                            )
                        )
                    break  # already tripped server error
                # Check common SQL error keywords
                text_low = resp.text.lower()
                if any(k in text_low for k in ["sql", "syntax", "unterminated", "database error", "sqlite", "mysql", "postgres"]):
                    evidence = "SQL/error keywords in response"
                    for p in base_params.keys():
                        findings.append(
                            DASTFinding(
                                url=test_url,
                                param=p,
                                technique="error",
                                response_code=resp.status_code,
                                response_time_ms=elapsed_ms,
                                evidence=evidence,
                            )
                        )
                    break
            except requests.RequestException as e:
                elapsed_ms = int((time.time() - start) * 1000)
                for p in base_params.keys():
                    findings.append(
                        DASTFinding(
                            url=test_url,
                            param=p,
                            technique="error",
                            response_code=0,
                            response_time_ms=elapsed_ms,
                            evidence=f"Request error: {e}",
                        )
                    )

        # Time-based
        for payload in SQLI_TIME_PAYLOADS:
            test_url = _inject_params(url, base_params, f"; {payload}; -- ")
            start = time.time()
            try:
                resp = requests.get(test_url, timeout=timeout)
                elapsed_ms = int((time.time() - start) * 1000)
                if elapsed_ms > 2500:  # 2.5s threshold indicative of sleep
                    for p in base_params.keys():
                        findings.append(
                            DASTFinding(
                                url=test_url,
                                param=p,
                                technique="time",
                                response_code=resp.status_code,
                                response_time_ms=elapsed_ms,
                                evidence="Response delay suggests time-based injection",
                            )
                        )
                    break
            except requests.RequestException:
                pass

    return findings