"""
Unit tests for tools/files.py path validation logic.

These tests focus on the security-critical path validation:
- paths outside allowed roots are rejected
- non-existent paths are rejected
- path traversal attempts are rejected
- valid paths are accepted
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

# Add the server directory to path so we can import tools
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestValidatePcapPath(unittest.TestCase):

    def _make_tool(self, allowed_roots: list[str]):
        """Return a validate_pcap_path function configured with given allowed roots."""
        # Patch ALLOWED_ROOTS for the duration of each test
        import tools.files as files_module
        original = files_module.ALLOWED_ROOTS
        files_module.ALLOWED_ROOTS = allowed_roots
        try:
            from tools.files import validate_pcap_path
            return validate_pcap_path
        finally:
            files_module.ALLOWED_ROOTS = original

    def test_path_outside_allowed_roots_is_rejected(self):
        """A path outside the configured allowed roots must be rejected."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            import tools.files as files_module
            original = files_module.ALLOWED_ROOTS
            try:
                files_module.ALLOWED_ROOTS = [allowed_dir]
                from tools.files import validate_pcap_path

                # Create a real file outside allowed dir
                with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
                    outside_path = f.name

                try:
                    result = validate_pcap_path(outside_path)
                    self.assertFalse(result["valid"], "Path outside allowed roots should be rejected")
                    self.assertIn("outside allowed roots", result["reason"].lower())
                finally:
                    os.unlink(outside_path)
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_nonexistent_path_is_rejected(self):
        """A path that doesn't exist must be rejected."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            import tools.files as files_module
            original = files_module.ALLOWED_ROOTS
            try:
                files_module.ALLOWED_ROOTS = [allowed_dir]
                from tools.files import validate_pcap_path

                nonexistent = os.path.join(allowed_dir, "does_not_exist.pcap")
                result = validate_pcap_path(nonexistent)
                self.assertFalse(result["valid"], "Non-existent path should be rejected")
                self.assertIn("does not exist", result["reason"].lower())
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_path_traversal_is_rejected(self):
        """Path traversal attempts (../../etc/passwd) must be rejected."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            import tools.files as files_module
            original = files_module.ALLOWED_ROOTS
            try:
                files_module.ALLOWED_ROOTS = [allowed_dir]
                from tools.files import validate_pcap_path

                # Construct a traversal attempt
                traversal = os.path.join(allowed_dir, "..", "..", "etc", "passwd")
                result = validate_pcap_path(traversal)
                self.assertFalse(result["valid"], "Path traversal should be rejected")
                # The normalized path should not start with allowed_dir
                normalized = result["normalized_path"]
                real_allowed = os.path.realpath(allowed_dir)
                self.assertFalse(
                    normalized.startswith(real_allowed + os.sep) or normalized == real_allowed,
                    f"Normalized path {normalized} should be outside {real_allowed}",
                )
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_valid_pcap_file_is_accepted(self):
        """A valid .pcap file inside allowed roots should be accepted."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            import tools.files as files_module
            original = files_module.ALLOWED_ROOTS
            try:
                files_module.ALLOWED_ROOTS = [allowed_dir]
                from tools.files import validate_pcap_path

                pcap_path = os.path.join(allowed_dir, "test.pcap")
                with open(pcap_path, "w") as f:
                    f.write("")  # Empty file is fine for path validation

                result = validate_pcap_path(pcap_path)
                self.assertTrue(result["valid"], f"Valid pcap should be accepted: {result['reason']}")
                self.assertEqual(result["type"], "file")
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_valid_pcapng_file_is_accepted(self):
        """A valid .pcapng file inside allowed roots should be accepted."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            import tools.files as files_module
            original = files_module.ALLOWED_ROOTS
            try:
                files_module.ALLOWED_ROOTS = [allowed_dir]
                from tools.files import validate_pcap_path

                pcapng_path = os.path.join(allowed_dir, "test.pcapng")
                with open(pcapng_path, "w") as f:
                    f.write("")

                result = validate_pcap_path(pcapng_path)
                self.assertTrue(result["valid"], f"Valid pcapng should be accepted: {result['reason']}")
                self.assertEqual(result["type"], "file")
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_wrong_extension_is_rejected(self):
        """A file with an unsupported extension should be rejected."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            import tools.files as files_module
            original = files_module.ALLOWED_ROOTS
            try:
                files_module.ALLOWED_ROOTS = [allowed_dir]
                from tools.files import validate_pcap_path

                txt_path = os.path.join(allowed_dir, "test.txt")
                with open(txt_path, "w") as f:
                    f.write("")

                result = validate_pcap_path(txt_path)
                self.assertFalse(result["valid"], "Wrong extension should be rejected")
                self.assertIn(".txt", result["reason"])
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_valid_directory_is_accepted(self):
        """A directory inside allowed roots should be accepted."""
        with tempfile.TemporaryDirectory() as allowed_dir:
            import tools.files as files_module
            original = files_module.ALLOWED_ROOTS
            try:
                files_module.ALLOWED_ROOTS = [allowed_dir]
                from tools.files import validate_pcap_path

                result = validate_pcap_path(allowed_dir)
                self.assertTrue(result["valid"], f"Valid directory should be accepted: {result['reason']}")
                self.assertEqual(result["type"], "directory")
            finally:
                files_module.ALLOWED_ROOTS = original

    def test_empty_path_is_rejected(self):
        """An empty path string should be rejected gracefully."""
        import tools.files as files_module
        from tools.files import validate_pcap_path

        result = validate_pcap_path("")
        self.assertFalse(result["valid"])
        self.assertIn("empty", result["reason"].lower())


if __name__ == "__main__":
    unittest.main()
