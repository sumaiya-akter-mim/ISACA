# Unified Security Report

- Severity: CRITICAL
- Risk Score: 100

## Summary
DAST found 2 potential SQLi vectors. SAST found 2 insecure patterns linked to parameters. Dump shows 4 password hashes with varying strengths.

## DAST Findings
- [error] http://127.0.0.1:5000/search?q=test%27 param=q code=500 time=10ms | HTTP 500 on error payload
- [error] http://127.0.0.1:5000/item?id=1%27 param=id code=500 time=12ms | HTTP 500 on error payload

## SAST Findings
- HIGH vulnerable_app\app.py:154 | SQL query built via f-string | rows = c.execute(f"SELECT user FROM users WHERE user LIKE '%{q}%' ").fetchall()
- HIGH vulnerable_app\app.py:164 | SQL query built via string concat/format | rows = c.execute("SELECT user FROM users WHERE id = " + item_id_raw).fetchall()

## Dump Audit Findings
- CRITICAL line 2 | MD5 | 21232f297a57a5a743894a0e4a801fc3
- HIGH line 2 | SHA1 | da4b9237bacccdf19c0760cab7aec4a8359010b0
- MEDIUM line 2 | bcrypt | $2b$12$C6UzMDM.H6dfI/f/IKxGhuYb8RZ8a6Z5S9YLeuYf1b9QZ/ZuQn66.
- LOW line 2 | Argon2 | $argon2id$v=19$m=65536,t=3,p=4$Wm9tYmllU2FsdA$K1bPq8Cq3ZJXzRys3vYUvA

## Recommended Fixes
- Use parameterized queries (prepared statements) for all DB interactions.
- Store passwords using modern KDFs (Argon2id, bcrypt, or PBKDF2).
- Rotate and reset compromised credentials; enable 2FA for sensitive accounts.
- Implement WAF rules and input validation for high-risk parameters.