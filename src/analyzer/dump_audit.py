import re
from dataclasses import dataclass
from typing import List, Tuple, Iterable


@dataclass
class DumpFinding:
    line_no: int
    hash_sample: str
    format: str
    severity: str


HASH_PATTERNS: List[Tuple[str, str, str]] = [
    # (regex, format_name, severity)
    (r"^[a-f0-9]{32}$", "MD5", "CRITICAL"),
    (r"^[a-f0-9]{40}$", "SHA1", "HIGH"),
    (r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt", "MEDIUM"),
    (r"^\$argon2(id|i)\$", "Argon2", "LOW"),
    (r"^pbkdf2:sha256:\d+:", "PBKDF2-SHA256", "LOW"),
]

# Heuristic column names likely to store password/hash material
PASSWORD_COLUMNS = {
    "password",
    "pass",
    "pwd",
    "passwd",
    "password_hash",
    "hash",
}


def _is_sql_dump(text: str) -> bool:
    t = text.upper()
    return ("INSERT INTO" in t) or ("UPDATE" in t) or ("CREATE TABLE" in t)


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if (s.startswith("'") and s.endswith("'")) or (s.startswith('"') and s.endswith('"')):
        return s[1:-1]
    return s


def _split_sql_args(s: str) -> List[str]:
    # Split by commas while respecting quotes and parentheses
    args: List[str] = []
    buf = []
    in_single = False
    in_double = False
    depth = 0
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "'" and not in_double:
            # Toggle single quotes; handle escaped single quotes ''
            if in_single and i + 1 < len(s) and s[i + 1] == "'":
                buf.append("'")
                i += 2
                continue
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "(" and not in_single and not in_double:
            depth += 1
        elif ch == ")" and not in_single and not in_double and depth > 0:
            depth -= 1
        if ch == "," and not in_single and not in_double and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    if buf:
        args.append("".join(buf).strip())
    return args


def _extract_parenthesized_groups(s: str) -> List[str]:
    # Return top-level (...) groups content without parentheses
    groups: List[str] = []
    buf = []
    in_single = False
    in_double = False
    depth = 0
    for i, ch in enumerate(s):
        if ch == "'" and not in_double:
            # handle doubled quotes inside single quoted literals
            if in_single and i + 1 < len(s) and s[i + 1] == "'":
                buf.append("''")
                continue
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if ch == "(" and not in_single and not in_double:
            if depth == 0:
                buf = []
            depth += 1
            if depth > 1:
                buf.append(ch)
            continue
        if ch == ")" and not in_single and not in_double:
            if depth > 1:
                buf.append(ch)
            depth -= 1
            if depth == 0:
                groups.append("".join(buf))
            continue
        if depth > 0:
            buf.append(ch)
    return groups


def _extract_candidates_from_insert(stmt: str) -> Iterable[str]:
    # Attempt to parse: INSERT INTO table [(col1,col2,...)] VALUES (...),(...),...
    up = stmt.upper()
    if "INSERT INTO" not in up:
        return []
    # Split into optional column list and values part
    # Rough regex-less parse: find 'VALUES'
    try:
        idx = up.index("VALUES")
    except ValueError:
        return []
    header = stmt[:idx]
    values_part = stmt[idx + len("VALUES"):]
    # Column list inside parentheses in header (last group)
    header_groups = _extract_parenthesized_groups(header)
    columns: List[str] = []
    if header_groups:
        columns = [c.strip().strip('"').strip("'") for c in _split_sql_args(header_groups[-1])]
    # Values may contain multiple tuples
    value_groups = _extract_parenthesized_groups(values_part)
    candidates: List[str] = []
    for vg in value_groups:
        vals = _split_sql_args(vg)
        if columns:
            # Map columns to values
            for idx_col, col in enumerate(columns):
                if col.lower() in PASSWORD_COLUMNS and idx_col < len(vals):
                    candidates.append(_strip_quotes(vals[idx_col]))
        else:
            # No column list; fall back to any value that looks like a hash
            for v in vals:
                candidates.append(_strip_quotes(v))
    return candidates


def _extract_candidates_from_update(stmt: str) -> Iterable[str]:
    # Parse: UPDATE table SET col1=val1, col2=val2 WHERE ...
    up = stmt.upper()
    if "UPDATE" not in up or " SET " not in up:
        return []
    try:
        idx = up.index(" SET ")
    except ValueError:
        return []
    set_part = stmt[idx + len(" SET ") :]
    # Split assignments by commas respecting quotes
    assigns = _split_sql_args(set_part)
    candidates: List[str] = []
    for a in assigns:
        if "=" in a:
            col, val = a.split("=", 1)
            if col.strip().strip('"').strip("'").lower() in PASSWORD_COLUMNS:
                candidates.append(_strip_quotes(val))
    return candidates


def identify_hashes_from_dump(dump_text: str) -> List[DumpFinding]:
    findings: List[DumpFinding] = []
    if _is_sql_dump(dump_text):
        # Process statement by statement (split by semicolon, naive but sufficient for common dumps)
        statements = [s.strip() for s in dump_text.split(";") if s.strip()]
        for idx_stmt, stmt in enumerate(statements, start=1):
            candidates: List[str] = []
            candidates.extend(list(_extract_candidates_from_insert(stmt)))
            candidates.extend(list(_extract_candidates_from_update(stmt)))

            # If no candidates by columns, still try quoted strings in the statement
            if not candidates:
                # Extract quoted literals
                candidates.extend([_strip_quotes(m) for m in re.findall(r"'([^']*)'|\"([^\"]*)\"", stmt)])

            for token in candidates:
                tok = token.strip()
                if not tok:
                    continue
                matched = False
                for pattern, fmt, sev in HASH_PATTERNS:
                    if re.search(pattern, tok):
                        findings.append(
                            DumpFinding(line_no=idx_stmt, hash_sample=tok[:80], format=fmt, severity=sev)
                        )
                        matched = True
                        break
                if not matched:
                    # Only record unknowns that are alnum and reasonably long (to avoid noise)
                    if re.match(r"^[A-Za-z0-9$:/.,_\-]{12,}$", tok):
                        findings.append(
                            DumpFinding(line_no=idx_stmt, hash_sample=tok[:80], format="Unknown", severity="INFO")
                        )
    else:
        # Fallback: line-by-line tokens
        for i, line in enumerate(dump_text.splitlines(), start=1):
            token = line.strip()
            for pattern, fmt, sev in HASH_PATTERNS:
                if re.search(pattern, token):
                    findings.append(
                        DumpFinding(line_no=i, hash_sample=token[:80], format=fmt, severity=sev)
                    )
                    break
            else:
                if token:
                    findings.append(
                        DumpFinding(line_no=i, hash_sample=token[:80], format="Unknown", severity="INFO")
                    )
    return findings