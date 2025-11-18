import unittest
from src.analyzer.dast import scan_sql_injection


class TestDAST(unittest.TestCase):
    def test_builds_findings_on_unreachable_host(self):
        # Unreachable host should still produce findings via request errors
        urls = ["http://127.0.0.1:59999/search?q=test"]
        findings = scan_sql_injection(urls, timeout=0.5)
        self.assertTrue(len(findings) >= 1)


if __name__ == "__main__":
    unittest.main()