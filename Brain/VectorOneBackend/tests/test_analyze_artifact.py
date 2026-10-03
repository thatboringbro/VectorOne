import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Controllers.analyzeArtifact import analyze


class AnalyzeArtifactTests(unittest.TestCase):
    @patch("Controllers.analyzeArtifact.check_virustotal", return_value={"malicious": 1, "suspicious": 0})
    @patch("Controllers.analyzeArtifact.check_abuse_ch", return_value={"malicious": False})
    def test_analyze_marks_hash_as_malicious_when_external_sources_flag_it(self, mock_abuse, mock_vt):
        self.assertEqual(analyze("hash-flagged"), "malicious")

    @patch("Controllers.analyzeArtifact.check_virustotal", return_value={"malicious": 0, "suspicious": 2})
    @patch("Controllers.analyzeArtifact.check_abuse_ch", return_value={"malicious": False})
    def test_analyze_marks_hash_as_suspicious_when_external_sources_are_suspicious(self, mock_abuse, mock_vt):
        self.assertEqual(analyze("hash-suspicious"), "suspicious")


if __name__ == "__main__":
    unittest.main()
