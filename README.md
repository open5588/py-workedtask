# py-workedtask (Javelin Anti-Cheat)

Minimal anti-cheat guards for C++ (`AntiCheat.cpp`) and Python (`anti_cheat.py`):

- **Debugger detection**: Detects attached debuggers (`IsDebuggerPresent` / PEB `BeingDebugged`).
- **Suspicious process scanning**: Detects known reverse-engineering and cheat tools (`cheatengine.exe`, `x64dbg.exe`, `ollydbg.exe`, `ida.exe`, `ida64.exe`, `scylla.exe`, `processhacker.exe`, `httpdebuggerui.exe`).
- **Self-integrity verification**:
  - **C++ (`AntiCheat.cpp`)**: Computes the CRC32 and/or SHA-256 of the running executable (with safe long-path resolution and deterministic config-slot exclusion) and compares against build-time constants (`JAVELIN_EXPECTED_CRC32`, `JAVELIN_EXPECTED_SHA256`).
  - **Python (`anti_cheat.py`)**: Computes the SHA-256 of the script file (`__file__`) and compares against the `JAVELIN_EXPECTED_SHA256` environment variable (or `--expected-sha256` CLI flag).

---

## Integrity Verification Setup

### 1. Python (`anti_cheat.py`)

#### Compute the expected SHA-256 of `anti_cheat.py`

```bash
python3 anti_cheat.py --print-sha256
```

#### Set `JAVELIN_EXPECTED_SHA256` and run

**Linux / macOS (bash/zsh):**
```bash
export JAVELIN_EXPECTED_SHA256="$(python3 anti_cheat.py --print-sha256)"
python3 anti_cheat.py
```

**Windows (PowerShell):**
```powershell
$env:JAVELIN_EXPECTED_SHA256 = (python .\anti_cheat.py --print-sha256).Trim()
python .\anti_cheat.py
```

- When `JAVELIN_EXPECTED_SHA256` is unset or empty, the integrity check is skipped (development mode).
- When `JAVELIN_EXPECTED_SHA256` is set and the script file has been modified (or the digest is malformed), `anti_cheat.py` prints an error to `stderr` and performs a guarded exit (`0xC0C`, non-zero exit status).

---

### 2. C++ (`AntiCheat.cpp`)

`AntiCheat.cpp` supports optional build-time constants `JAVELIN_EXPECTED_CRC32` and `JAVELIN_EXPECTED_SHA256`. The embedded configuration slot is normalized during self-hashing so that recompiling with the baseline hash does not invalidate the hash itself.

#### Step 1: Build the baseline binary and print its CRC32 / SHA-256

**MSVC (Windows):**
```powershell
cl /std:c++17 /EHsc AntiCheat.cpp /Fe:AntiCheat.exe
.\AntiCheat.exe --print-crc32
.\AntiCheat.exe --print-sha256
```

**GCC / Clang / MinGW:**
```bash
c++ -std=c++17 -O2 AntiCheat.cpp -o AntiCheat
./AntiCheat --print-crc32
./AntiCheat --print-sha256
```

#### Step 2: Rebuild with `JAVELIN_EXPECTED_CRC32` and/or `JAVELIN_EXPECTED_SHA256`

**MSVC (Windows):**
```powershell
cl /std:c++17 /EHsc /DJAVELIN_EXPECTED_CRC32=0xA64E1C62u /DJAVELIN_EXPECTED_SHA256="\"<64-hex-sha256>\"" AntiCheat.cpp /Fe:AntiCheat.exe
.\AntiCheat.exe
```

**GCC / Clang / MinGW:**
```bash
CRC=$(./AntiCheat --print-crc32)
SHA=$(./AntiCheat --print-sha256)
c++ -std=c++17 -O2 -DJAVELIN_EXPECTED_CRC32="${CRC}u" -DJAVELIN_EXPECTED_SHA256="\"${SHA}\"" AntiCheat.cpp -o AntiCheat
./AntiCheat
```

- Leaving `JAVELIN_EXPECTED_CRC32` as `0u` and `JAVELIN_EXPECTED_SHA256` as `""` (the defaults) disables the respective check.
- On a CRC32 or SHA-256 mismatch, the executable prints an error message to `stderr` and exits with code `0xC0C`.

---

## Guarded Exit Codes

| Exit Code (Hex) | Meaning |
| --- | --- |
| `0x0` | All checks passed |
| `0xDEB` | Debugger detected |
| `0xBAD` | Suspicious process detected |
| `0xC0C` | Self-integrity verification failed (CRC32 / SHA-256 mismatch) |

---

## Running Tests

```bash
python3 -m unittest -v test_integrity.py
```
