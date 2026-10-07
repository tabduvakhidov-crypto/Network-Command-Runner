"""
Unit tests for Network Command Runner
"""

import os
import unittest
from network_engine import (
    extract_valid_ips,
    check_port_open,
    sanitize_commands,
    save_audit_reports,
    ExecutionResult,
)


class TestNetworkEngine(unittest.TestCase):
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

    def test_save_audit_reports(self):
        test_dir = os.path.join(os.path.dirname(__file__), "test_reports")
        results = [
            ExecutionResult(
                ip="192.168.1.1",
                status="SUCCESS",
                credential_used="Admin Set 1",
                attempts=["Admin Set 1"],
                raw_output="crypto key generate rsa modulus 2048\nip ssh version 2",
                duration_seconds=1.45,
            ),
        ]
        csv_file, logs_dir = save_audit_reports(results, output_dir=test_dir)
        self.assertTrue(os.path.exists(csv_file))
        self.assertTrue(os.path.exists(logs_dir))

        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

