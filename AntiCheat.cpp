// AntiCheat.cpp
// Javelin Project - Minimal Anti-Cheat guards
// Features: debugger detection, suspicious process scan, self-integrity (CRC32 & SHA-256)

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#else
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static const char* kTag = "[Javelin AntiCheat] ";

// Exit codes (non-zero in both full 32-bit Windows status and low 8-bit POSIX wait status)
static constexpr int kDebuggerExitCode = 0xDEB;
static constexpr int kSuspiciousProcessExitCode = 0xBAD;
static constexpr int kIntegrityExitCode = 0xC0C;

// --- Build-time integrity configuration ---
#ifndef JAVELIN_EXPECTED_CRC32
#define JAVELIN_EXPECTED_CRC32 0u  // Set at build time (e.g., -DJAVELIN_EXPECTED_CRC32=0x12345678u)
#endif

#ifndef JAVELIN_EXPECTED_SHA256
#define JAVELIN_EXPECTED_SHA256 ""  // Set at build time (e.g., -DJAVELIN_EXPECTED_SHA256="64-hex-chars")
#endif

static constexpr char kIntegrityBeginMarker[] = "JAVELIN_INTEGRITY_CFG_BEGIN_V1";
static constexpr char kIntegrityEndMarker[] = "JAVELIN_INTEGRITY_CFG_END_V1!!";

#pragma pack(push, 1)
struct IntegrityConfig {
    char beginMarker[sizeof(kIntegrityBeginMarker)];
    uint32_t expectedCrc32;
    char expectedSha256[65];
    char endMarker[sizeof(kIntegrityEndMarker)];
};
#pragma pack(pop)

static_assert(
    offsetof(IntegrityConfig, expectedCrc32) == sizeof(kIntegrityBeginMarker),
    "Unexpected padding before expectedCrc32"
);
static_assert(
    offsetof(IntegrityConfig, expectedSha256) ==
        sizeof(kIntegrityBeginMarker) + sizeof(uint32_t),
    "Unexpected padding before expectedSha256"
);
static_assert(
    offsetof(IntegrityConfig, endMarker) ==
        sizeof(kIntegrityBeginMarker) + sizeof(uint32_t) + 65,
    "Unexpected padding before endMarker"
);

static volatile const IntegrityConfig kIntegrityConfig = {
    "JAVELIN_INTEGRITY_CFG_BEGIN_V1",
    static_cast<uint32_t>(JAVELIN_EXPECTED_CRC32),
    JAVELIN_EXPECTED_SHA256,
    "JAVELIN_INTEGRITY_CFG_END_V1!!"
};

// --- Configurable lists ---
static std::vector<std::string> kSuspiciousProcesses = {
    "cheatengine.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "httpdebuggerui.exe",
    "ida.exe",
    "ida64.exe",
    "scylla.exe",
    "processhacker.exe"
};

// --- Utils ---
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

// Simple CRC32 (IEEE 802.3 polynomial 0xEDB88320)
static uint32_t crc32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

// Self-contained FIPS 180-4 SHA-256 implementation
static std::string sha256Hex(const std::vector<uint8_t>& data) {
    static constexpr std::array<uint32_t, 64> kRoundConstants = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };

    auto rotr = [](uint32_t x, uint32_t n) -> uint32_t {
        return (x >> n) | (x << (32u - n));
    };

    uint32_t h0 = 0x6a09e667u;
    uint32_t h1 = 0xbb67ae85u;
    uint32_t h2 = 0x3c6ef372u;
    uint32_t h3 = 0xa54ff53au;
    uint32_t h4 = 0x510e527fu;
    uint32_t h5 = 0x9b05688cu;
    uint32_t h6 = 0x1f83d9abu;
    uint32_t h7 = 0x5be0cd19u;

    const uint64_t bitLen = static_cast<uint64_t>(data.size()) * 8ULL;
    std::vector<uint8_t> padded = data;
    padded.push_back(0x80u);
    while ((padded.size() % 64u) != 56u) {
        padded.push_back(0x00u);
    }
    for (int i = 7; i >= 0; --i) {
        padded.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xFFu));
    }

    for (size_t chunkOffset = 0; chunkOffset < padded.size(); chunkOffset += 64u) {
        uint32_t w[64]{};
        for (size_t i = 0; i < 16u; ++i) {
            size_t j = chunkOffset + (i * 4u);
            w[i] = (static_cast<uint32_t>(padded[j]) << 24u) |
                   (static_cast<uint32_t>(padded[j + 1]) << 16u) |
                   (static_cast<uint32_t>(padded[j + 2]) << 8u) |
                   static_cast<uint32_t>(padded[j + 3]);
        }
        for (size_t i = 16u; i < 64u; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7u) ^ rotr(w[i - 15], 18u) ^ (w[i - 15] >> 3u);
            uint32_t s1 = rotr(w[i - 2], 17u) ^ rotr(w[i - 2], 19u) ^ (w[i - 2] >> 10u);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (size_t i = 0; i < 64u; ++i) {
            uint32_t S1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + kRoundConstants[i] + w[i];
            uint32_t S0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    const uint32_t words[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint32_t word : words) {
        oss << std::setw(8) << word;
    }
    return oss.str();
}

#ifdef _WIN32
using NativePath = std::wstring;

static bool readFile(const NativePath& path, std::vector<uint8_t>& out) {
    out.clear();
    FILE* file = _wfopen(path.c_str(), L"rb");
    if (!file) return false;

    uint8_t buffer[65536];
    while (true) {
        size_t count = std::fread(buffer, 1, sizeof(buffer), file);
        if (count > 0) {
            out.insert(out.end(), buffer, buffer + count);
        }
        if (count < sizeof(buffer)) {
            if (std::ferror(file)) {
                std::fclose(file);
                return false;
            }
            break;
        }
    }
    std::fclose(file);
    return !out.empty();
}

static bool getSelfPath(NativePath& pathOut, const char* /*argv0*/ = nullptr) {
    // Dynamically grow buffer so long Windows paths (>= MAX_PATH) are never truncated.
    std::vector<wchar_t> buffer(MAX_PATH);
    while (buffer.size() <= 32768u) {
        SetLastError(ERROR_SUCCESS);
        DWORD len = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) {
            return false;
        }
        if (len < buffer.size() && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            pathOut.assign(buffer.data(), len);
            return true;
        }
        buffer.resize(buffer.size() * 2u);
    }
    return false;
}

static NativePath toNativePath(const std::string& utf8Path) {
    if (utf8Path.empty()) return NativePath();
    int needed = MultiByteToWideChar(CP_UTF8, 0, utf8Path.c_str(), -1, nullptr, 0);
    if (needed <= 1) return NativePath(utf8Path.begin(), utf8Path.end());
    std::wstring result(static_cast<size_t>(needed - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8Path.c_str(), -1, &result[0], needed);
    return result;
}
#else
using NativePath = std::string;

static bool readFile(const NativePath& path, std::vector<uint8_t>& out) {
    out.clear();
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    uint8_t buffer[65536];
    while (f.read(reinterpret_cast<char*>(buffer), sizeof(buffer)) || f.gcount() > 0) {
        out.insert(out.end(), buffer, buffer + static_cast<size_t>(f.gcount()));
        if (f.eof()) break;
    }
    return !f.bad() && !out.empty();
}

static bool getSelfPath(NativePath& pathOut, const char* argv0 = nullptr) {
#if defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    if (size > 0) {
        std::vector<char> buf(size);
        if (_NSGetExecutablePath(buf.data(), &size) == 0) {
            char resolved[PATH_MAX]{};
            if (realpath(buf.data(), resolved) != nullptr) {
                pathOut = resolved;
                return true;
            }
            pathOut = buf.data();
            return true;
        }
    }
#else
    std::vector<char> buf(4096);
    while (buf.size() <= 65536u) {
        ssize_t count = readlink("/proc/self/exe", buf.data(), buf.size());
        if (count < 0) break;
        if (static_cast<size_t>(count) < buf.size()) {
            pathOut.assign(buf.data(), static_cast<size_t>(count));
            return true;
        }
        buf.resize(buf.size() * 2u);
    }
#endif
    if (argv0 && argv0[0] != '\0') {
        char resolved[PATH_MAX]{};
        if (realpath(argv0, resolved) != nullptr) {
            pathOut = resolved;
            return true;
        }
        pathOut = argv0;
        return true;
    }
    return false;
}

static NativePath toNativePath(const std::string& path) {
    return path;
}
#endif

// Zero out embedded IntegrityConfig payload and volatile linker metadata so
// a build-time constant compiled with -DJAVELIN_EXPECTED_CRC32 / -DJAVELIN_EXPECTED_SHA256
// matches the hash computed from the baseline binary without circularity.
static void normalizeExecutableBytes(std::vector<uint8_t>& bytes) {
    constexpr size_t kBeginSize = sizeof(kIntegrityBeginMarker);
    constexpr size_t kPayloadSize = sizeof(uint32_t) + 65u;
    constexpr size_t kEndSize = sizeof(kIntegrityEndMarker);
    constexpr size_t kTotalConfigSize = kBeginSize + kPayloadSize + kEndSize;

    if (bytes.size() >= kTotalConfigSize) {
        for (size_t offset = 0; offset <= bytes.size() - kTotalConfigSize; ++offset) {
            if (std::memcmp(bytes.data() + offset, kIntegrityBeginMarker, kBeginSize) == 0 &&
                std::memcmp(
                    bytes.data() + offset + kBeginSize + kPayloadSize,
                    kIntegrityEndMarker,
                    kEndSize
                ) == 0) {
                std::memset(bytes.data() + offset + kBeginSize, 0, kPayloadSize);
            }
        }
    }

    // Normalize PE TimeDateStamp and OptionalHeader CheckSum if binary is a Windows PE image
    if (bytes.size() >= 0x40u && bytes[0] == 'M' && bytes[1] == 'Z') {
        uint32_t peOffset = 0;
        std::memcpy(&peOffset, bytes.data() + 0x3Cu, sizeof(uint32_t));
        if (peOffset <= bytes.size() - 24u &&
            bytes[peOffset] == 'P' && bytes[peOffset + 1] == 'E' &&
            bytes[peOffset + 2] == 0 && bytes[peOffset + 3] == 0) {
            // IMAGE_FILE_HEADER.TimeDateStamp is at peOffset + 4 + 4
            std::memset(bytes.data() + peOffset + 8u, 0, sizeof(uint32_t));
            const size_t optOffset = static_cast<size_t>(peOffset) + 24u;
            if (optOffset + 68u <= bytes.size()) {
                uint16_t magic = 0;
                std::memcpy(&magic, bytes.data() + optOffset, sizeof(uint16_t));
                // CheckSum is at offset 64 in both PE32 (0x10B) and PE32+ (0x20B) optional headers
                if (magic == 0x10Bu || magic == 0x20Bu) {
                    std::memset(bytes.data() + optOffset + 64u, 0, sizeof(uint32_t));
                }
            }
        }
    }

#if defined(__APPLE__)
    // Normalize Mach-O LC_UUID and ad-hoc LC_CODE_SIGNATURE blob so two builds
    // differing only in JAVELIN_EXPECTED_CRC32 / JAVELIN_EXPECTED_SHA256 hash identically.
    if (bytes.size() >= sizeof(mach_header_64)) {
        uint32_t magic = 0;
        std::memcpy(&magic, bytes.data(), sizeof(uint32_t));
        if (magic == MH_MAGIC_64) {
            mach_header_64 hdr{};
            std::memcpy(&hdr, bytes.data(), sizeof(mach_header_64));
            size_t cmdOffset = sizeof(mach_header_64);
            for (uint32_t i = 0; i < hdr.ncmds && cmdOffset + sizeof(load_command) <= bytes.size(); ++i) {
                load_command lc{};
                std::memcpy(&lc, bytes.data() + cmdOffset, sizeof(load_command));
                if (lc.cmdsize < sizeof(load_command) || cmdOffset + lc.cmdsize > bytes.size()) {
                    break;
                }
                if (lc.cmd == LC_UUID && lc.cmdsize >= sizeof(uuid_command)) {
                    std::memset(bytes.data() + cmdOffset + offsetof(uuid_command, uuid), 0, 16u);
                } else if (lc.cmd == LC_CODE_SIGNATURE && lc.cmdsize >= sizeof(linkedit_data_command)) {
                    linkedit_data_command sig{};
                    std::memcpy(&sig, bytes.data() + cmdOffset, sizeof(linkedit_data_command));
                    if (sig.dataoff < bytes.size() &&
                        sig.datasize <= bytes.size() - sig.dataoff) {
                        std::memset(bytes.data() + sig.dataoff, 0, sig.datasize);
                    }
                }
                cmdOffset += lc.cmdsize;
            }
        }
    }
#endif
}

static bool parseHexSha256(const std::string& input, std::string& normalizedOut) {
    std::string s = toLower(trim(input));
    if (s.rfind("0x", 0) == 0) {
        s = s.substr(2);
    } else if (s.rfind("sha256:", 0) == 0) {
        s = s.substr(7);
    }
    if (s.size() != 64u) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    normalizedOut = s;
    return true;
}

static bool parseUint32(const std::string& input, uint32_t& out) {
    std::string s = trim(input);
    if (s.empty()) return false;
    char* end = nullptr;
    unsigned long long val = std::strtoull(s.c_str(), &end, 0);
    if (end == s.c_str() || *end != '\0' || val > 0xFFFFFFFFULL) {
        return false;
    }
    out = static_cast<uint32_t>(val);
    return true;
}

static std::string readConfiguredSha256() {
    char buf[65]{};
    for (size_t i = 0; i < 64u; ++i) {
        char c = kIntegrityConfig.expectedSha256[i];
        buf[i] = c;
        if (c == '\0') break;
    }
    buf[64] = '\0';
    return std::string(buf);
}

// --- Checks ---
static bool checkDebugger() {
#ifdef _WIN32
    if (IsDebuggerPresent()) return true;

    // Secondary anti-debug: CheckBeingDebugged flag in PEB (best-effort)
#if defined(_MSC_VER) && defined(_M_IX86)
    // 32-bit: fs:[30h] -> PEB, offset 2 = BeingDebugged (BYTE)
    __try {
        BYTE* peb = reinterpret_cast<BYTE*>(__readfsdword(0x30));
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#elif defined(_MSC_VER) && defined(_M_X64)
    // 64-bit: gs:[60h] -> PEB
    __try {
        BYTE* peb = reinterpret_cast<BYTE*>(__readgsqword(0x60));
        if (peb && peb[2]) return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
#endif
    return false;
}

static bool checkSuspiciousProcesses() {
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        std::string name = toLower(pe.szExeFile);
        for (const auto& bad : kSuspiciousProcesses) {
            if (name == toLower(bad)) {
                CloseHandle(snap);
                return true;
            }
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
#endif
    return false;
}

static bool checkSelfIntegrity(uint32_t expectedCrc, const NativePath& targetPath = NativePath()) {
    NativePath path = targetPath;
    if (path.empty() && !getSelfPath(path)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    const uint32_t rawCrc = crc32(bytes);
    if (rawCrc == expectedCrc) return true;

    normalizeExecutableBytes(bytes);
    const uint32_t normalizedCrc = crc32(bytes);
    return normalizedCrc == expectedCrc;
}

static bool checkSelfIntegritySha256(
    const std::string& expectedHex,
    const NativePath& targetPath = NativePath()
) {
    std::string normalizedExpected;
    if (!parseHexSha256(expectedHex, normalizedExpected)) return false;

    NativePath path = targetPath;
    if (path.empty() && !getSelfPath(path)) return false;

    std::vector<uint8_t> bytes;
    if (!readFile(path, bytes)) return false;

    const std::string rawDigest = sha256Hex(bytes);
    if (rawDigest == normalizedExpected) return true;

    normalizeExecutableBytes(bytes);
    const std::string normalizedDigest = sha256Hex(bytes);
    return normalizedDigest == normalizedExpected;
}

int main(int argc, char* argv[]) {
    bool printCrc32 = false;
    bool printSha256 = false;
    bool hasCliCrc32 = false;
    uint32_t cliCrc32 = 0u;
    std::string cliSha256;
    std::string fileArg;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--print-crc32" || arg == "--print-self-crc32") {
            printCrc32 = true;
        } else if (arg == "--print-sha256" || arg == "--print-self-sha256") {
            printSha256 = true;
        } else if (arg == "--expected-crc32" && i + 1 < argc) {
            if (!parseUint32(argv[++i], cliCrc32)) {
                std::cerr << kTag << "Invalid --expected-crc32 value. Exiting.\n";
                return kIntegrityExitCode;
            }
            hasCliCrc32 = true;
        } else if (arg == "--expected-sha256" && i + 1 < argc) {
            cliSha256 = argv[++i];
        } else if (arg == "--file" && i + 1 < argc) {
            fileArg = argv[++i];
        }
    }

    NativePath targetPath = fileArg.empty() ? NativePath() : toNativePath(fileArg);
    if (targetPath.empty()) {
        getSelfPath(targetPath, argc > 0 ? argv[0] : nullptr);
    }

    if (printCrc32 || printSha256) {
        std::vector<uint8_t> bytes;
        if (targetPath.empty() || !readFile(targetPath, bytes)) {
            std::cerr << kTag << "Unable to read executable for hashing. Exiting.\n";
            return kIntegrityExitCode;
        }
        normalizeExecutableBytes(bytes);
        if (printCrc32) {
            std::cout << "0x" << std::uppercase << std::hex << std::setw(8)
                      << std::setfill('0') << crc32(bytes) << "\n";
        }
        if (printSha256) {
            std::cout << sha256Hex(bytes) << "\n";
        }
        return 0;
    }

    std::cout << kTag << "starting checks...\n";

    if (checkDebugger()) {
        std::cerr << kTag << "Debugger detected. Exiting.\n";
        return kDebuggerExitCode;
    }

    if (checkSuspiciousProcesses()) {
        std::cerr << kTag << "Suspicious process detected. Exiting.\n";
        return kSuspiciousProcessExitCode;
    }

    const uint32_t expectedCrc = hasCliCrc32 ? cliCrc32 : kIntegrityConfig.expectedCrc32;
    if (expectedCrc != 0u) {
        if (!checkSelfIntegrity(expectedCrc, targetPath)) {
            std::cerr << kTag << "Integrity check failed (CRC mismatch). Exiting.\n";
            return kIntegrityExitCode;
        }
    }

    std::string expectedSha = cliSha256;
    if (expectedSha.empty()) {
        expectedSha = readConfiguredSha256();
    }
    if (expectedSha.empty()) {
        const char* envSha = std::getenv("JAVELIN_EXPECTED_SHA256");
        if (envSha != nullptr) {
            expectedSha = trim(envSha);
        }
    }

    if (!expectedSha.empty()) {
        if (!checkSelfIntegritySha256(expectedSha, targetPath)) {
            std::cerr << kTag << "Integrity check failed (SHA-256 mismatch). Exiting.\n";
            return kIntegrityExitCode;
        }
    }

    std::cout << kTag << "All clear. Continue.\n";
    return 0;
}
