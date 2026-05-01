# qc_inspect

A command-line tool for inspecting Qualcomm firmware images — MELF, MBN, ELF, and more.  
Extracts ELF structure, MBNv7 Hash Table Segments, certificate chains, and **pkhash** values without needing a full Qualcomm toolchain.

> **Author:** [Littlenine](https://github.com/LittlenineEnnea)

---

## Features

- **ELF header & program header** parsing (32-bit and 64-bit, ARM / AArch64 / RISC-V)
- **MBNv7 Hash Table Segment** detection — works even when the segment is located outside the ELF (e.g. embedded in a flash partition image)
- **Segment hash** extraction (SHA256 / SHA384 / SHA512)
- **ECDSA signature** parsing (DER format, r/s values)
- **X.509 certificate chain** extraction and grouping (Root CA → SubCA → Leaf)
- **pkhash** computation (SHA256 & SHA384 of each certificate's public key)
- File integrity info: MD5, SHA256, size breakdown
- Color-coded terminal output with `-v` / `-vv` verbosity levels

---

## Supported File Types

| Extension | Description |
|-----------|-------------|
| `.melf`   | Qualcomm multi-image ELF (firehose, etc.) |
| `.mbn`    | Qualcomm MBN signed image |
| `.elf`    | Standard ELF with or without MBN signing |

---

## Download

Pre-built binaries are available on the [Releases](../../releases) page — no Python required.

| Platform       | Binary |
|----------------|--------|
| Linux x64      | `qc_inspect_linux_x64` |
| Windows x64    | `qc_inspect_windows_x64.exe` |
| Windows arm64  | `qc_inspect_windows_arm64.exe` |
| macOS arm64    | `qc_inspect_macos_arm64` |

On Linux / macOS, make the binary executable first:
```bash
chmod +x qc_inspect_linux_x64
./qc_inspect_linux_x64 image.melf
```

---

## Usage (Python)

**Requirements:** Python 3.8+, `openssl` command available in PATH (standard on Linux/macOS, install [Win32 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html) on Windows)

```bash
# Basic output
python qc_inspect.py image.melf

# Full certificate chain details + all pkhash values
python qc_inspect.py image.melf -v

# Include raw hex dumps of all fields
python qc_inspect.py image.melf -vv
```

---

## Output Overview

```
============================================================
  Qualcomm Firmware Inspector — xiaomi_8750_firehose_noauth.melf
============================================================
  Author : Littlenine (github.com/LittlenineEnnea)
  File   : xiaomi_8750_firehose_noauth.melf
  Size   : 1,697,740 bytes  (0x19e7cc)
  MD5    : ...
  SHA256 : ...

[ELF Header]
  Class                        ELF32
  Machine                      0xf3  RISC-V
  Entry point                  0x22126000
  Program header count         2

[Program Headers]
  Idx  Type   Offset       VirtAddr     FileSize     ...

[Scanning for MBNv7 Hash Table Segment]
  Found 1 Hash Table Segment(s)
  Hash Table Segment @ 0x2aa20
    Magic                      0x0015555a
    Version                    3
    Hash alg                   SHA384
    Hash[0] @ 0x2abf4          0ff7c3f1...

[Certificate Chains]
  Total unique certs: 6  (roots: 2, non-root: 4)

  Certificate Chain 1
    [Root CA]  @ offset 0x2c03d
      Subject : CN=SRoT MBNv7 Image Signing Root CA 6, ...
      PubKey SHA256 (pkhash): 3dd04a60...

  Certificate Chain 2
    [Root CA]  @ offset 0x2bd8c+...
      Subject : CN=Generated Xiaomi Root CA, ...
      PubKey SHA256 (pkhash): b74b70c2...
      PubKey SHA384 (pkhash): 5a0eea4b...

============================================================
  SUMMARY
============================================================
[Certificate Chains & pkhash]
  Root CA #1: CN=Generated Xiaomi Root CA ...
  pkhash SHA256        b74b70c2da44eb76f5ef918a268ccfa79268a4e9...
  pkhash SHA384        5a0eea4b9396a3c2d87ede35bf1bcce9a3e2111e...
```

---

## Verbosity Levels

| Flag | Output |
|------|--------|
| *(none)* | ELF info, Hash Table Segment summary, certificate chain overview, Root CA pkhash |
| `-v`  | All of the above + full per-cert details (subject, issuer, validity, sig alg) + ECDSA r/s values + pkhash for every cert |
| `-vv` | All of the above + raw hex dumps of ELF segments and certificate DER data |

---

## Building from Source

```bash
pip install pyinstaller
pyinstaller --onefile --name qc_inspect qc_inspect.py
./dist/qc_inspect image.melf
```

Or just use the [GitHub Actions workflow](.github/workflows/build.yml) — push a `v*` tag to automatically build all platforms and publish a release.

---

## License

This project is for research and educational purposes.  
Use responsibly and only on firmware you have the right to inspect.
