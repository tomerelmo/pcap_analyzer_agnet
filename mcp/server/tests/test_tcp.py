"""
Unit tests for tools/tcp.py — TCP reset detection.

Full integration tests require real PCAP files. These tests cover:
- path validation is enforced before running tshark
- result structure matches expected schema
- truncation logic works correctly
- graceful handling of empty tshark output
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestFindResets(unittest.TestCase):

    def test_invalid_path_returns_error(self):
        """If the path is invalid, find_resets should return an error dict without running tshark."""
        import tools.files as files_module
        original = files_module.ALLOWED_ROOTS
        try:
            files_module.ALLOWED_ROOTS = ["/data/pcaps"]
            from tools.tcp import find_resets

            result = find_resets("/outside/allowed/root/test.pcap")
            self.assertFalse(result.get("error") is None or result.get("resets") == [],
                             "Should return error for invalid path")
            self.assertEqual(result["resets"], [])
            self.assertEqual(result["count"], 0)
            self.assertFalse(result["truncated"])
        finally:
            files_module.ALLOWED_ROOTS = original

    def test_result_structure(self):
        """Result dict must always have the expected keys."""
        import tempfile
        import tools.files as files_module
        original = files_module.ALLOWED_ROOTS

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                files_module.ALLOWED_ROOTS = [tmpdir]

                # Create a dummy pcap file
                pcap_path = os.path.join(tmpdir, "test.pcap")
                with open(pcap_path, "wb") as f:
                    # Write minimal pcap global header (magic number only, tshark will fail gracefully)
                    f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00")

                from tools.tcp import find_resets

                # Mock run_command to avoid needing real tshark
                with patch("tools.tcp.run_command") as mock_run:
                    mock_run.return_value = ("", "", 0)
                    result = find_resets(pcap_path)

                self.assertIn("file", result)
                self.assertIn("resets", result)
                self.assertIn("count", result)
                self.assertIn("truncated", result)
                self.assertIsInstance(result["resets"], list)
                self.assertIsInstance(result["count"], int)
                self.assertIsInstance(result["truncated"], bool)
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_truncation_respected(self):
        """Results should be truncated to max_results lines."""
        import tempfile
        import tools.files as files_module
        original = files_module.ALLOWED_ROOTS

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                files_module.ALLOWED_ROOTS = [tmpdir]

                pcap_path = os.path.join(tmpdir, "test.pcap")
                with open(pcap_path, "wb") as f:
                    f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00")

                # Build tshark-like output: 10 reset lines
                reset_lines = "\n".join(
                    f"{i}\t{i * 0.1:.3f}\t10.0.0.1\t10.0.0.2\t{1000+i}\t80"
                    for i in range(1, 11)
                )

                from tools.tcp import find_resets

                with patch("tools.tcp.run_command") as mock_run:
                    mock_run.return_value = (reset_lines, "", 0)
                    with patch("tools.tcp.get_max_results") as mock_max:
                        mock_max.return_value = 5
                        result = find_resets(pcap_path)

                self.assertEqual(len(result["resets"]), 5)
                self.assertEqual(result["count"], 10)  # Total count before truncation
                self.assertTrue(result["truncated"])
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_empty_output_returns_empty_list(self):
        """Empty tshark output (no resets) should return empty list, not error."""
        import tempfile
        import tools.files as files_module
        original = files_module.ALLOWED_ROOTS

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                files_module.ALLOWED_ROOTS = [tmpdir]

                pcap_path = os.path.join(tmpdir, "test.pcap")
                with open(pcap_path, "wb") as f:
                    f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00")

                from tools.tcp import find_resets

                with patch("tools.tcp.run_command") as mock_run:
                    mock_run.return_value = ("", "", 0)
                    result = find_resets(pcap_path)

                self.assertEqual(result["resets"], [])
                self.assertEqual(result["count"], 0)
                self.assertFalse(result["truncated"])
                self.assertNotIn("error", result)
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_reset_entry_fields(self):
        """Each reset entry must have all expected fields."""
        import tempfile
        import tools.files as files_module
        original = files_module.ALLOWED_ROOTS

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                files_module.ALLOWED_ROOTS = [tmpdir]

                pcap_path = os.path.join(tmpdir, "test.pcap")
                with open(pcap_path, "wb") as f:
                    f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00")

                single_reset = "42\t1.234000\t192.168.1.1\t192.168.1.2\t54321\t80"

                from tools.tcp import find_resets

                with patch("tools.tcp.run_command") as mock_run:
                    mock_run.return_value = (single_reset, "", 0)
                    result = find_resets(pcap_path)

                self.assertEqual(len(result["resets"]), 1)
                entry = result["resets"][0]
                self.assertIn("frame_number", entry)
                self.assertIn("time_relative", entry)
                self.assertIn("ip_src", entry)
                self.assertIn("ip_dst", entry)
                self.assertIn("tcp_srcport", entry)
                self.assertIn("tcp_dstport", entry)

                self.assertEqual(entry["frame_number"], "42")
                self.assertEqual(entry["ip_src"], "192.168.1.1")
                self.assertEqual(entry["tcp_dstport"], "80")
            finally:
                files_module.ALLOWED_ROOTS = original


if __name__ == "__main__":
    unittest.main()
