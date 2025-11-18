import unittest
from src.analyzer.sast import analyze_python_file


WEAK_CODE = """
import hashlib
from flask import request

def store(p):
    password = p
    h = hashlib.md5(p.encode()).hexdigest()

def query():
    q = request.args['q']
    sql = "SELECT * FROM t WHERE q='" + q + "'"
    cursor.execute(sql)
"""


class TestSAST(unittest.TestCase):
    def test_detects_insecure_patterns(self):
        findings = analyze_python_file("file.py", WEAK_CODE)
        issues = [f.issue for f in findings]
        self.assertTrue(any("Insecure hash function" in i for i in issues))
        self.assertTrue(any("SQL query built" in i for i in issues))
        self.assertTrue(any("Request parameter accessed" in i for i in issues))


if __name__ == "__main__":
    unittest.main()