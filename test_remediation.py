"""
Unit and integration tests for Switch Remediation Tool
"""

import os
import unittest
from remediation_engine import (
    extract_valid_ips,
    check_port_open,
    sanitize_commands,
    save_audit_reports,
    RemediationResult,
)


class TestRemediationEngine(unittest.TestCase):
    def test_sanitize_commands(self):
        raw = [
            "configure terminal",
            "crypto key generate rsa modulus 2048",
            "ip ssh version 2",
            "end",
            "write memory",
        ]
        cmds, should_save, save_cmd = sanitize_commands(raw)
        self.assertEqual(cmds, ["crypto key generate rsa modulus 2048", "ip ssh version 2"])
        self.assertTrue(should_save)
        self.assertEqual(save_cmd, "write memory")
    def test_extract_valid_ips(self):
        sample_input = """
        Switch-Core-01: 192.168.1.1
        10.20.30.40, 172.16.0.5
        192.168.1.1/24 (duplicate)
        invalid: 999.999.1.1, 0.0.0.0, 256.1.1.1
        random text 10.0.0.1:22 and 10.0.0.2
        """
        ips = extract_valid_ips(sample_input)
        expected = ["192.168.1.1", "10.20.30.40", "172.16.0.5", "10.0.0.1", "10.0.0.2"]
        self.assertEqual(ips, expected)

    def test_check_port_open_unreachable(self):
        # 192.0.2.1 is TEST-NET-1 (RFC 5737), should timeout quickly
        is_open, msg = check_port_open("192.0.2.1", port=22, timeout=0.5)
        self.assertFalse(is_open)
        self.assertTrue("timed out" in msg or "unreachable" in msg.lower())

    def test_save_audit_reports(self):
        test_dir = os.path.join(os.path.dirname(__file__), "test_reports")
        results = [
            RemediationResult(
                ip="192.168.1.1",
                status="SUCCESS",
                credential_used="Admin Set 1",
                attempts=["Admin Set 1"],
                raw_output="ip ssh version 2\nwrite memory",
                duration_seconds=1.45,
            ),
            RemediationResult(
                ip="192.168.1.2",
                status="AUTH_FAILED",
                credential_used=None,
                attempts=["Admin Set 1", "Admin Set 2"],
                error_message="All 2 credential sets failed authentication.",
                duration_seconds=3.2,
            ),
        ]
        csv_file, logs_dir = save_audit_reports(results, output_dir=test_dir)
        self.assertTrue(os.path.exists(csv_file))
        self.assertTrue(os.path.exists(logs_dir))

        # Clean up test output
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

