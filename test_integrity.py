#!/usr/bin/env python3
"""Regression test suite for Javelin Anti-Cheat integrity verification (Python & C++)."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import anti_cheat

REPO_ROOT = Path(__file__).resolve().parent
SCRIPT_PATH = REPO_ROOT / "anti_cheat.py"
CPP_SOURCE = REPO_ROOT / "AntiCheat.cpp"


class PythonIntegrityTests(unittest.TestCase):
    def test_compute_sha256_matches_known_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample = Path(tmp_dir) / "sample.py"
            payload = b"print('javelin integrity check')\n"
            sample.write_bytes(payload)

            expected = hashlib.sha256(payload).hexdigest()
            self.assertEqual(anti_cheat.compute_sha256(sample), expected)
            self.assertEqual(anti_cheat.sha256_file(sample), expected)
            self.assertTrue(anti_cheat.verify_script_integrity(sample, expected))
            self.assertTrue(anti_cheat.check_script_integrity(sample, expected.upper()))

    def test_tampered_script_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample = Path(tmp_dir) / "sample.py"
            sample.write_bytes(b"print('original')\n")
            baseline_hash = anti_cheat.compute_sha256(sample)

            sample.write_bytes(b"print('tampered')\n")
            self.assertFalse(anti_cheat.verify_script_integrity(sample, baseline_hash))

    def test_expected_hash_normalization_and_validation(self) -> None:
        self.assertIsNone(anti_cheat.expected_script_sha256({}))
        self.assertIsNone(
            anti_cheat.expected_script_sha256({anti_cheat.EXPECTED_HASH_ENV: "   "})
        )

        valid_upper = "A" * 64
        self.assertEqual(
            anti_cheat.expected_script_sha256({anti_cheat.EXPECTED_HASH_ENV: valid_upper}),
            "a" * 64,
        )
        self.assertEqual(
            anti_cheat.normalize_sha256("0x" + ("B" * 64)),
            "b" * 64,
        )
        self.assertEqual(
            anti_cheat.normalize_sha256("sha256:" + ("C" * 64)),
            "c" * 64,
        )

        for invalid in ["short", "z" * 64, "0" * 63, "0" * 65]:
            with self.assertRaises(ValueError):
                anti_cheat.expected_script_sha256(
                    {anti_cheat.EXPECTED_HASH_ENV: invalid}
                )

    def test_verify_self_integrity_passes_when_unset_or_matching(self) -> None:
        actual = anti_cheat.compute_sha256(SCRIPT_PATH)
        self.assertTrue(anti_cheat.verify_self_integrity(environ={}))
        self.assertTrue(
            anti_cheat.verify_self_integrity(
                environ={anti_cheat.EXPECTED_HASH_ENV: actual}
            )
        )
        self.assertFalse(
            anti_cheat.verify_self_integrity(
                environ={anti_cheat.EXPECTED_HASH_ENV: "0" * 64}
            )
        )
        self.assertFalse(
            anti_cheat.verify_self_integrity(
                environ={anti_cheat.EXPECTED_HASH_ENV: "invalid-digest"}
            )
        )

    def test_main_accepts_matching_env_hash(self) -> None:
        actual = anti_cheat.compute_sha256(SCRIPT_PATH)
        stdout = io.StringIO()
        with patch.dict(
            os.environ, {anti_cheat.EXPECTED_HASH_ENV: actual}, clear=False
        ), redirect_stdout(stdout):
            code = anti_cheat.main(["--integrity-only"])
        self.assertEqual(code, 0)
        self.assertIn("All clear. Continue.", stdout.getvalue())

    def test_main_exits_nonzero_on_mismatch_or_malformed_hash(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.dict(
            os.environ, {anti_cheat.EXPECTED_HASH_ENV: "f" * 64}, clear=False
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            code = anti_cheat.main(["--integrity-only"])
        self.assertEqual(code, anti_cheat.EXIT_INTEGRITY_FAILED)
        self.assertIn("SHA-256 mismatch", stderr.getvalue())

        stdout_malformed = io.StringIO()
        stderr_malformed = io.StringIO()
        with patch.dict(
            os.environ, {anti_cheat.EXPECTED_HASH_ENV: "not-valid-hex"}, clear=False
        ), redirect_stdout(stdout_malformed), redirect_stderr(stderr_malformed):
            code_malformed = anti_cheat.main(["--integrity-only"])
        self.assertEqual(code_malformed, anti_cheat.EXIT_INTEGRITY_FAILED)
        self.assertIn("Integrity check failed", stderr_malformed.getvalue())

    def test_print_sha256_flag(self) -> None:
        stdout = io.StringIO()
        with patch.dict(
            os.environ, {anti_cheat.EXPECTED_HASH_ENV: "invalid"}, clear=False
        ), redirect_stdout(stdout):
            code = anti_cheat.main(["--print-sha256"])
        self.assertEqual(code, 0)
        self.assertEqual(stdout.getvalue().strip(), anti_cheat.compute_sha256(SCRIPT_PATH))

    def test_cli_subprocess_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            copied_script = Path(tmp_dir) / "anti_cheat.py"
            shutil.copy2(SCRIPT_PATH, copied_script)

            res_hash = subprocess.run(
                [sys.executable, str(copied_script), "--print-sha256"],
                capture_output=True,
                text=True,
                check=True,
            )
            baseline_sha = res_hash.stdout.strip()
            self.assertEqual(len(baseline_sha), 64)

            env = os.environ.copy()
            env[anti_cheat.EXPECTED_HASH_ENV] = baseline_sha

            res_ok = subprocess.run(
                [sys.executable, str(copied_script), "--integrity-only"],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_ok.returncode, 0)
            self.assertIn("All clear. Continue.", res_ok.stdout)

            # Tamper with the script copy
            with copied_script.open("ab") as handle:
                handle.write(b"\n# tampered\n")

            res_tampered = subprocess.run(
                [sys.executable, str(copied_script), "--integrity-only"],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res_tampered.returncode, 0)
            self.assertIn("SHA-256 mismatch", res_tampered.stderr)

    def test_runtime_guards_mocked(self) -> None:
        class FakeProc:
            def __init__(self, name: str) -> None:
                self.info = {"name": name}

        fake_psutil = types.SimpleNamespace(
            process_iter=lambda _attrs: iter([FakeProc("CheatEngine.exe")])
        )
        with patch.object(anti_cheat, "psutil", fake_psutil):
            found = anti_cheat.detect_suspicious_processes()
            self.assertIsNotNone(found)
            self.assertEqual(found.lower(), "cheatengine.exe")

        safe_psutil = types.SimpleNamespace(
            process_iter=lambda _attrs: iter([FakeProc("explorer.exe"), FakeProc("python.exe")])
        )
        with patch.object(anti_cheat, "psutil", safe_psutil):
            self.assertIsNone(anti_cheat.detect_suspicious_processes())

        with patch.object(anti_cheat, "HAS_WIN", False):
            self.assertFalse(anti_cheat.is_debugger_present())


class CppIntegrityTests(unittest.TestCase):
    @staticmethod
    def _find_cxx() -> Optional[str]:
        for candidate in ("c++", "clang++", "g++"):
            found = shutil.which(candidate)
            if found:
                return found
        return None

    def test_cpp_self_integrity_build_and_tamper_detection(self) -> None:
        cxx = self._find_cxx()
        if cxx is None:
            self.skipTest("No C++ compiler found on PATH")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            baseline_bin = tmp_path / "anticheat_baseline"
            verified_bin = tmp_path / "anticheat_verified"
            tampered_bin = tmp_path / "anticheat_tampered"

            # 1. Compile baseline executable without expected hashes
            subprocess.run(
                [
                    cxx,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    str(CPP_SOURCE),
                    "-o",
                    str(baseline_bin),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            crc_res = subprocess.run(
                [str(baseline_bin), "--print-crc32"],
                check=True,
                capture_output=True,
                text=True,
            )
            expected_crc = crc_res.stdout.strip()
            self.assertTrue(expected_crc.startswith("0x") and len(expected_crc) == 10)

            sha_res = subprocess.run(
                [str(baseline_bin), "--print-sha256"],
                check=True,
                capture_output=True,
                text=True,
            )
            expected_sha = sha_res.stdout.strip()
            self.assertEqual(len(expected_sha), 64)

            # 2. Recompile embedding both JAVELIN_EXPECTED_CRC32 and JAVELIN_EXPECTED_SHA256
            subprocess.run(
                [
                    cxx,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    f"-DJAVELIN_EXPECTED_CRC32={expected_crc}u",
                    f'-DJAVELIN_EXPECTED_SHA256="{expected_sha}"',
                    str(CPP_SOURCE),
                    "-o",
                    str(verified_bin),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            # Verified binary passes self-integrity check
            run_verified = subprocess.run(
                [str(verified_bin)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(run_verified.returncode, 0, run_verified.stderr)
            self.assertIn("All clear. Continue.", run_verified.stdout)

            # 3. Mismatched CRC32 or SHA-256 fails with guarded exit
            run_bad_crc = subprocess.run(
                [str(verified_bin), "--expected-crc32", "0xDEADBEEF"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(run_bad_crc.returncode, 0)
            self.assertIn("CRC mismatch", run_bad_crc.stderr)

            run_bad_sha = subprocess.run(
                [str(verified_bin), "--expected-sha256", "0" * 64],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(run_bad_sha.returncode, 0)
            self.assertIn("SHA-256 mismatch", run_bad_sha.stderr)

            # 4. Tampering with a copy of the binary is detected
            shutil.copy2(verified_bin, tampered_bin)
            with tampered_bin.open("ab") as handle:
                handle.write(b"\x90\x90\x90\x90")

            run_tampered = subprocess.run(
                [str(verified_bin), "--file", str(tampered_bin)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(run_tampered.returncode, 0)
            self.assertIn("Integrity check failed", run_tampered.stderr)


if __name__ == "__main__":
    unittest.main()
