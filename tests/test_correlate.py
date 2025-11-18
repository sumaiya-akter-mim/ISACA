import unittest
from src.analyzer.correlate import correlate
from src.analyzer.dast import DASTFinding
from src.analyzer.sast import SASTFinding
from src.analyzer.dump_audit import DumpFinding


class TestCorrelate(unittest.TestCase):
    def test_risk_scoring(self):
        dast = [DASTFinding(url="http://x/search?q=test'", param="q", technique="error", response_code=500, response_time_ms=10, evidence="HTTP 500")]
        sast = [SASTFinding(file="app.py", line=10, issue="SQL query built via f-string", severity="HIGH", code_snippet="", param=None)]
        dump = [DumpFinding(line_no=1, hash_sample="21232f...", format="MD5", severity="CRITICAL")]
        risk = correlate(dast, sast, dump)
        self.assertGreaterEqual(risk.score, 70)
        self.assertIn(risk.severity, ["CRITICAL", "HIGH"]) 


if __name__ == "__main__":
    unittest.main()