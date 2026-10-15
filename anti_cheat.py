#!/usr/bin/env python3
"""Javelin Anti-Cheat Python Monitor & Self-Integrity Guard.

Features:
- Debugger detection (Windows IsDebuggerPresent / CheckRemoteDebuggerPresent)
- Suspicious process detection (via psutil when installed)
- Runtime self-integrity verification (SHA-256 of script file vs JAVELIN_EXPECTED_SHA256)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import string
import sys
from pathlib import Path
from typing import Mapping, Optional, Sequence, Union

try:
    import psutil  # type: ignore
    HAS_PSUTIL = True
except ImportError:
    psutil = None  # type: ignore
    HAS_PSUTIL = False

try:
    import ctypes
    HAS_CTYPES = True
except ImportError:
    ctypes = None  # type: ignore
    HAS_CTYPES = False

HAS_WIN = bool(HAS_CTYPES and sys.platform == "win32")

TAG = "[Javelin AntiCheat] "
EXPECTED_HASH_ENV = "JAVELIN_EXPECTED_SHA256"
HASH_ENV_VAR = EXPECTED_HASH_ENV

EXIT_OK = 0
EXIT_DEBUGGER = 0xDEB
EXIT_SUSPICIOUS_PROCESS = 0xBAD
EXIT_INTEGRITY_FAILED = 0xC0C
INTEGRITY_FAILURE_EXIT_CODE = EXIT_INTEGRITY_FAILED

SUSPICIOUS_PROCESSES = [
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe",
]

PathLike = Union[str, os.PathLike, Path]


def resolve_script_path(script_path: Optional[PathLike] = None) -> Path:
    """Resolve the target script path, defaulting to this module's __file__."""
    target = Path(script_path) if script_path is not None else Path(__file__)
    return target.resolve()


def compute_sha256(file_path: PathLike) -> str:
    """Compute the lowercase hex SHA-256 digest of a file."""
    path = Path(file_path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: PathLike) -> str:
    """Alias for compute_sha256."""
    return compute_sha256(path)


def normalize_sha256(expected_hash: Optional[str]) -> Optional[str]:
    """Normalize and validate an expected SHA-256 hex string.

    Returns None when expected_hash is None or empty/whitespace-only.
    Raises ValueError if non-empty and not a valid 64-character hex digest.
    """
    if expected_hash is None:
        return None
    cleaned = expected_hash.strip()
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if lowered.startswith("0x"):
        lowered = lowered[2:]
    elif lowered.startswith("sha256:"):
        lowered = lowered[7:]
    if len(lowered) != 64 or any(ch not in string.hexdigits for ch in lowered):
        raise ValueError(
            f"{EXPECTED_HASH_ENV} must contain a valid 64-character hexadecimal SHA-256 digest"
        )
    return lowered


def expected_script_sha256(
    environ: Optional[Mapping[str, str]] = None,
    cli_expected: Optional[str] = None,
) -> Optional[str]:
    """Retrieve and validate the expected SHA-256 from CLI override or environment."""
    if cli_expected is not None and cli_expected.strip():
        return normalize_sha256(cli_expected)
    env = os.environ if environ is None else environ
    return normalize_sha256(env.get(EXPECTED_HASH_ENV))


def verify_script_integrity(script_path: PathLike, expected_hash: str) -> bool:
    """Verify a script file's SHA-256 against expected_hash in constant time."""
    normalized = normalize_sha256(expected_hash)
    if normalized is None:
        return True
    actual = compute_sha256(script_path)
    return hmac.compare_digest(actual, normalized)


def check_script_integrity(path: PathLike, expected_sha256: str) -> bool:
    """Alias for verify_script_integrity."""
    return verify_script_integrity(path, expected_sha256)


def verify_self_integrity(
    expected_hash: Optional[str] = None,
    script_path: Optional[PathLike] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> bool:
    """Verify the running script's SHA-256 against expected_hash or JAVELIN_EXPECTED_SHA256.

    Returns True if no expected hash is configured or if the digest matches.
    Returns False if the configured hash is malformed, the script cannot be read,
    or the digest does not match.
    """
    try:
        expected = expected_script_sha256(environ=environ, cli_expected=expected_hash)
    except ValueError:
        return False

    if expected is None:
        return True

    try:
        target = resolve_script_path(script_path)
        actual = compute_sha256(target)
    except OSError:
        return False

    return hmac.compare_digest(actual, expected)


def is_debugger_present() -> bool:
    """Detect whether a debugger is attached (Windows API with graceful fallback)."""
    if not HAS_WIN or not HAS_CTYPES:
        return False
    try:
        kernel32 = getattr(ctypes, "windll", None)
        if kernel32 is None:
            return False
        return bool(kernel32.kernel32.IsDebuggerPresent())
    except Exception:
        return False


def detect_suspicious_processes() -> Optional[str]:
    """Scan running processes for known cheat/debugger tools using psutil if available."""
    if psutil is None:
        return None
    suspicious_lower = {name.lower() for name in SUSPICIOUS_PROCESSES}
    try:
        for proc in psutil.process_iter(["name"]):
            info = getattr(proc, "info", None) or {}
            proc_name = info.get("name")
            if not proc_name:
                continue
            name_lower = proc_name.lower()
            if name_lower in suspicious_lower or any(bad in name_lower for bad in suspicious_lower):
                return proc_name
    except Exception:
        return None
    return None


def run_checks(
    expected_sha256: Optional[str] = None,
    script_path: Optional[PathLike] = None,
    environ: Optional[Mapping[str, str]] = None,
    skip_runtime_guards: bool = False,
) -> int:
    """Run anti-cheat checks and return the resulting status code."""
    print(f"{TAG}starting checks...")

    if not skip_runtime_guards:
        if is_debugger_present():
            print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
            return EXIT_DEBUGGER

        bad_proc = detect_suspicious_processes()
        if bad_proc is not None:
            print(f"{TAG}Suspicious process detected ({bad_proc}). Exiting.", file=sys.stderr)
            return EXIT_SUSPICIOUS_PROCESS

    try:
        configured_hash = expected_script_sha256(environ=environ, cli_expected=expected_sha256)
    except ValueError as exc:
        print(f"{TAG}Integrity check failed ({exc}). Exiting.", file=sys.stderr)
        return EXIT_INTEGRITY_FAILED

    if configured_hash is not None:
        target = resolve_script_path(script_path)
        try:
            if not verify_script_integrity(target, configured_hash):
                print(
                    f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.",
                    file=sys.stderr,
                )
                return EXIT_INTEGRITY_FAILED
        except OSError as exc:
            print(
                f"{TAG}Integrity check failed (unable to read script: {exc}). Exiting.",
                file=sys.stderr,
            )
            return EXIT_INTEGRITY_FAILED

    print(f"{TAG}All clear. Continue.")
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point for the Python anti-cheat monitor."""
    parser = argparse.ArgumentParser(description="Javelin Anti-Cheat Python Monitor")
    parser.add_argument(
        "--print-sha256",
        action="store_true",
        help="Print the SHA-256 digest of the script file and exit",
    )
    parser.add_argument(
        "--expected-sha256",
        default=None,
        help=f"Expected 64-character hex SHA-256 (overrides {EXPECTED_HASH_ENV})",
    )
    parser.add_argument(
        "--file",
        default=None,
        help="Target script path to hash/verify (defaults to this script)",
    )
    parser.add_argument(
        "--integrity-only",
        action="store_true",
        help="Run only the script integrity check",
    )
    args = parser.parse_args(argv)

    target = resolve_script_path(args.file)
    if args.print_sha256:
        try:
            print(compute_sha256(target))
            return EXIT_OK
        except OSError as exc:
            print(f"{TAG}Unable to read script: {exc}. Exiting.", file=sys.stderr)
            return EXIT_INTEGRITY_FAILED

    return run_checks(
        expected_sha256=args.expected_sha256,
        script_path=target,
        skip_runtime_guards=args.integrity_only,
    )


if __name__ == "__main__":
    sys.exit(main())
