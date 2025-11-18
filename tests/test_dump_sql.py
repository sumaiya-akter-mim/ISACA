import unittest
from src.analyzer.dump_audit import identify_hashes_from_dump


SQL_DUMP = """
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  password TEXT NOT NULL
);

INSERT INTO users (id, username, password) VALUES
  (1, 'admin', '21232f297a57a5a743894a0e4a801fc3'),
  (2, 'bob', 'da4b9237bacccdf19c0760cab7aec4a8359010b0'),
  (3, 'alice', '$2b$12$C6UzMDM.H6dfI/f/IKxGhuYb8RZ8a6Z5S9YLeuYf1b9QZ/ZuQn66.'),
  (4, 'charlie', '$argon2id$v=19$m=65536,t=3,p=4$Wm9tYmllU2FsdA$K1bPq8Cq3ZJXzRys3vYUvA');
"""


class TestDumpSQL(unittest.TestCase):
    def test_parses_insert_values_and_identifies_hashes(self):
        findings = identify_hashes_from_dump(SQL_DUMP)
        formats = [f.format for f in findings]
        self.assertIn("MD5", formats)
        self.assertIn("SHA1", formats)
        self.assertIn("bcrypt", formats)
        self.assertIn("Argon2", formats)


if __name__ == "__main__":
    unittest.main()